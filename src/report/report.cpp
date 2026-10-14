#include "report/report.hpp"
#include <algorithm>
#include <cmath>
#include <fstream>
#include <map>
#include <numeric>
#include <optional>
#include <random>
#include <stdexcept>
#include <string>
namespace turtle::report {
namespace {
using Json=nlohmann::json;
double weighted(const std::vector<double>& sorted, unsigned first, unsigned last) {
    long double sum=0;
    const auto n=sorted.size();
    for (std::size_t i=0;i<n;++i) {
        const auto begin=std::max(8*i,first*n), end=std::min(8*(i+1),last*n);
        if (end>begin) sum+=static_cast<long double>(sorted[i])*(end-begin);
    }
    return static_cast<double>(sum/((last-first)*n));
}
bool boundary(const Json& e) {
    const auto l=e.at("location").get<std::string>();
    return l=="implementation_boundary" || l=="framework";
}
std::uint64_t time(const Json& e) { return e.at("monotonic_ns").get<std::uint64_t>(); }
std::string kind(const Json& e) { return e.at("kind").get<std::string>(); }
Json distribution(const std::vector<double>& values) {
    const auto s=statistics(values);
    return {{"count",s.count},{"minimum",s.minimum},{"maximum",s.maximum},
            {"stq1",s.stq[0]},{"stq2",s.stq[1]},{"stq3",s.stq[2]},{"values",values}};
}
void svg(const std::filesystem::path& path,const std::vector<double>& values) {
    auto sorted=values; std::sort(sorted.begin(),sorted.end());
    const auto low=sorted.front(),high=sorted.back();
    std::ofstream out(path);out.exceptions(std::ios::badbit|std::ios::failbit);
    out<<"<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"640\" height=\"320\">"
          "<rect width=\"640\" height=\"320\" fill=\"white\"/>"
          "<text x=\"40\" y=\"20\">Empirical cumulative distribution (raw ns)</text>"
          "<path d=\"M40 40V280H620\" fill=\"none\" stroke=\"black\"/>"
          "<polyline fill=\"none\" stroke=\"#164b87\" points=\"";
    for (std::size_t i=0;i<sorted.size();++i) {
        const double x=high>low ? 40+580*(sorted[i]-low)/(high-low) : 330;
        out<<x<<','<<280-240*static_cast<double>(i+1)/sorted.size()<<' ';
    }
    out<<"\"/><text x=\"40\" y=\"305\">"<<low<<" ns</text>"
        <<"<text x=\"500\" y=\"305\">"<<high<<" ns</text></svg>\n";
}
}
Statistics statistics(std::span<const double> values) {
    if (values.empty()) throw std::invalid_argument("statistics require samples");
    std::vector<double> sorted(values.begin(),values.end());
    for (double v:sorted) if (!std::isfinite(v)) throw std::invalid_argument("nonfinite sample");
    std::sort(sorted.begin(),sorted.end());
    return {sorted.size(),sorted.front(),sorted.back(),
            {weighted(sorted,1,3),weighted(sorted,3,5),weighted(sorted,5,7)}};
}
Comparison compare(std::span<const double> a,std::span<const double> b,
                   std::uint64_t seed,std::size_t repetitions) {
    if (a.empty()||b.empty()||repetitions<2) throw std::invalid_argument("bootstrap needs samples");
    const double difference=statistics(b).stq[1]-statistics(a).stq[1];
    std::mt19937_64 rng(seed);
    std::uniform_int_distribution<std::size_t> da(0,a.size()-1),db(0,b.size()-1);
    std::vector<double> aa(a.size()),bb(b.size()),differences;
    differences.reserve(repetitions);
    for (std::size_t i=0;i<repetitions;++i) {
        for (auto& v:aa) v=a[da(rng)];
        for (auto& v:bb) v=b[db(rng)];
        differences.push_back(statistics(bb).stq[1]-statistics(aa).stq[1]);
    }
    std::sort(differences.begin(),differences.end());
    const auto lo=differences[static_cast<std::size_t>(0.025*(repetitions-1))];
    const auto hi=differences[static_cast<std::size_t>(0.975*(repetitions-1))];
    return {difference,lo,hi,lo>0||hi<0};
}
Json partition(const Json& header,const std::vector<Json>& input) {
    Json results=Json::array();
    for (const auto& conn:header.at("connections")) {
        if (conn.value("warmup",false)) continue;
        const auto index=conn.at("index").get<std::size_t>();
        std::vector<const Json*> events;
        for (const auto& e:input) if (e.at("connection")==index && boundary(e)) events.push_back(&e);
        Json result={{"connection",index},{"valid",false}};
        if (events.empty()) {result["reason"]="missing boundary events";results.push_back(result);continue;}
        std::optional<std::uint64_t> start,end;
        const Json* start_event=nullptr;
        const Json* end_event=nullptr;
        const bool client=header.at("role")=="client";
        for (const auto* e:events) {
            const auto k=kind(*e);
            if (!start && ((client && k=="CALL_BEGIN" && e->at("call")=="handshake") ||
                (!client && k=="IO_RECV_RETURN" && e->value("transferred",0ULL)>0))) {start=time(*e);start_event=e;}
            if (k=="CALL_END" && e->at("call")==(client?"app_recv":"app_send") &&
                e->value("result",0LL)==2) {end=time(*e);end_event=e;}
        }
        if (!start || !end || *end<*start) {
            result["reason"]="missing successful measurement boundaries";results.push_back(result);continue;
        }
        std::uint64_t computation=0,io=0,wait=0,gap=0;
        bool in_call=false,in_io=false,in_wait=false,consistent=true;
        std::uint64_t previous=time(*events.front());
        Json segments=Json::array();
        for (const auto* e:events) {
            const auto now=time(*e);
            if (now<previous) {consistent=false;break;}
            const auto lo=std::max(previous,*start),hi=std::min(now,*end);
            const char* label=in_io?"io":in_wait?"wait":in_call?"computation":"gap";
            if (hi>lo) {
                auto* total=in_io?&io:in_wait?&wait:in_call?&computation:&gap;
                *total+=hi-lo;
                segments.push_back({{"kind",label},{"begin_ns",lo},{"end_ns",hi},{"elapsed_ns",hi-lo}});
            }
            const auto k=kind(*e);
            if (k=="CALL_BEGIN") {if(in_call)consistent=false;in_call=true;}
            else if(k=="CALL_END"){if(!in_call||in_io)consistent=false;in_call=false;}
            else if(k=="IO_SEND_ENTER"||k=="IO_RECV_ENTER"){if(in_io)consistent=false;in_io=true;}
            else if(k=="IO_SEND_RETURN"||k=="IO_RECV_RETURN"){if(!in_io)consistent=false;in_io=false;}
            else if(k=="WAIT_BEGIN"){if(in_wait||in_io||in_call)consistent=false;in_wait=true;}
            else if(k=="WAIT_END"){if(!in_wait)consistent=false;in_wait=false;}
            previous=now;
        }
        const auto elapsed=*end-*start;
        consistent=consistent && computation+io+wait+gap==elapsed;
        result.update({{"valid",consistent},{"start_ns",*start},{"end_ns",*end},
            {"elapsed_ns",elapsed},{"computation_ns",computation},{"io_ns",io},
            {"wait_ns",wait},{"gap_ns",gap},{"segments",segments},
            {"end_definition","successful_application_call_end"}});
        for(const char* metric:{"thread_cpu_ns","cycles","instructions"}) {
            result[metric]=nullptr;
            const bool supported=std::string(metric)=="thread_cpu_ns" ||
                header.value("perf_complete",false);
            if(supported && start_event->contains(metric) && end_event->contains(metric) &&
               !start_event->at(metric).is_null() && !end_event->at(metric).is_null()) {
                const auto a=start_event->at(metric).get<std::uint64_t>();
                const auto b=end_event->at(metric).get<std::uint64_t>();
                if(b>=a)result[metric]=b-a;
            }
        }
        result["heap_peak_bytes"]=nullptr;
        for(const auto* e:events) {
            if(time(*e)<*start || time(*e)>*end || !e->contains("heap") || e->at("heap").is_null())continue;
            const auto peak=e->at("heap").at("interval_peak").get<std::uint64_t>();
            if(result["heap_peak_bytes"].is_null() || peak>result["heap_peak_bytes"].get<std::uint64_t>())
                result["heap_peak_bytes"]=peak;
        }
        if (!consistent) result["reason"]="boundary nesting/order or interval conservation failed";
        results.push_back(result);
    }
    return results;
}
Json summarize(const std::filesystem::path& input,const std::filesystem::path& output) {
    std::vector<std::filesystem::path> paths;
    if (std::filesystem::is_regular_file(input)) paths.push_back(input);
    else for (const auto& entry:std::filesystem::recursive_directory_iterator(input))
        if (entry.is_regular_file() && (entry.path().filename()=="client.jsonl" ||
            entry.path().filename()=="server.jsonl")) paths.push_back(entry.path());
    std::sort(paths.begin(),paths.end());
    Json samples=Json::array(),groups=Json::array();
    struct Group {
        Json dimensions;
        std::map<std::string,std::vector<double>> metrics;
        std::map<std::uint64_t,std::vector<double>> batches;
    };
    std::map<std::string,Group> collected;
    std::size_t invalid=0;
    for (const auto& path:paths) {
        std::ifstream file(path);std::string line;
        if (!std::getline(file,line)) throw std::runtime_error("empty raw record: "+path.string());
        auto header=Json::parse(line);
        if (header.at("type")!="sample" || header.at("schema")!=1) throw std::runtime_error("unsupported raw record schema");
        std::vector<Json> events;
        while(std::getline(file,line)) if(!line.empty()) events.push_back(Json::parse(line));
        auto parts=partition(header,events);
        bool valid=header.value("valid",false);
        for(const auto& p:parts) valid=valid && p.value("valid",false);
        if(parts.empty()) valid=false;
        samples.push_back({{"path",path.string()},{"sample",header.at("sample")},
            {"role",header.at("role")},{"valid",valid},{"invalid_reason",header.value("invalid_reason","")},{"connections",parts}});
        if(!valid){++invalid;continue;}
        Json dimensions={{"role",header.at("role")},{"profile_hash",header.at("profile_hash")},
            {"environment_hash",header.at("environment_hash")},{"mode",header.at("mode")},
            {"observation_level",header.value("observation_level","L0")},
            {"warmups",header.at("config").value("warmups",0)},
            {"loaded_context",header.value("loaded_context_size",0)>0},
            {"library",header.at("declaration").value("library","")},
            {"library_version",header.at("declaration").value("version","")},
            {"is_mock",header.at("declaration").value("is_mock",false)},{"correction","raw"},
            {"timing_interpretation",header.at("mode")=="timing"?"performance":"diagnostic_only"}};
        auto& group=collected[dimensions.dump()];group.dimensions=dimensions;
        for(const auto& p:parts) {
            for(const auto* metric:{"elapsed_ns","computation_ns","io_ns","wait_ns","gap_ns","thread_cpu_ns","cycles","instructions","heap_peak_bytes"})
                if(p.contains(metric) && !p.at(metric).is_null())group.metrics[metric].push_back(p.at(metric).get<double>());
            group.batches[header.at("batch").get<std::uint64_t>()].push_back(p.at("elapsed_ns").get<double>());
        }
    }
    std::filesystem::create_directories(output);
    std::size_t group_index=0;
    for (const auto& [key,group]:collected) {
        (void)key;
        Json item={{"dimensions",group.dimensions},{"metrics",Json::object()},{"batches",Json::array()}};
        for(const auto& [name,values]:group.metrics) item["metrics"][name]=distribution(values);
        std::vector<double> batch_stq;
        for(const auto& [batch,values]:group.batches) {
            auto d=distribution(values);d["batch"]=batch;item["batches"].push_back(d);
            batch_stq.push_back(d["stq2"].get<double>());
        }
        item["batch_stq2_range_ns"]=*std::max_element(batch_stq.begin(),batch_stq.end())-
                                     *std::min_element(batch_stq.begin(),batch_stq.end());
        const auto filename="distribution-"+std::to_string(group_index++)+".svg";
        svg(output/filename,group.metrics.at("elapsed_ns"));
        item["distribution_svg"]=filename;groups.push_back(item);
    }
    Json comparisons=Json::array();
    for(std::size_t a=0;a<groups.size();++a)for(std::size_t b=a+1;b<groups.size();++b) {
        auto da=groups[a]["dimensions"],db=groups[b]["dimensions"];
        if(da["mode"]!="timing" || db["mode"]!="timing")continue;
        for(const char* field:{"profile_hash","library","library_version"}){da.erase(field);db.erase(field);}
        if(da!=db)continue;
        const auto av=groups[a]["metrics"]["elapsed_ns"]["values"].get<std::vector<double>>();
        const auto bv=groups[b]["metrics"]["elapsed_ns"]["values"].get<std::vector<double>>();
        const auto c=compare(av,bv);
        const auto batch_range=std::max(groups[a]["batch_stq2_range_ns"].get<double>(),
                                        groups[b]["batch_stq2_range_ns"].get<double>());
        comparisons.push_back({{"group_a",a},{"group_b",b},{"difference_b_minus_a_ns",c.difference},
            {"lower_95_ns",c.lower},{"upper_95_ns",c.upper},{"distinguishable",c.distinguishable},
            {"method","independent_percentile_bootstrap"},{"seed",1},{"replicates",2000},
            {"batch_variation_warning",batch_range>std::abs(c.difference)}});
    }
    Json result={{"schema",1},{"comparisons",comparisons},{"groups",groups},{"samples",samples},{"invalid_samples",invalid},
        {"notes",{"Endpoint roles are never added together.","Kernel timestamps are excluded from L0 partitions.",
                  "Raw boundary times; no calibration subtraction is applied.",
                  "Missing or multiplexed counters are not synthesized."}}};
    std::ofstream out(output/"summary.json");out.exceptions(std::ios::badbit|std::ios::failbit);
    out<<result.dump(2)<<'\n';return result;
}
}
