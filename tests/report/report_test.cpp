#include "report/report.hpp"
#include <algorithm>
#include <cassert>
#include <cmath>
#include <iostream>
#include <numeric>
#include <fstream>
#include <unistd.h>
int main(){
    using namespace turtle::report;
    for(std::size_t n=1;n<40;++n){
        std::vector<double> v(n);std::iota(v.begin(),v.end(),1.0);std::reverse(v.begin(),v.end());
        const auto got=statistics(v);
        std::vector<double> repeated;
        for(double x:v)for(int i=0;i<8;++i)repeated.push_back(x);
        std::sort(repeated.begin(),repeated.end());
        for(int q=0;q<3;++q){
            const auto begin=(1+2*q)*n,end=(3+2*q)*n;
            double expected=std::accumulate(repeated.begin()+begin,repeated.begin()+end,0.0)/(2*n);
            assert(std::abs(got.stq[q]-expected)<1e-10);
        }
        std::sort(v.begin(),v.end());assert(statistics(v).stq==got.stq);
    }
    const std::vector<double> a{1,1,1},b{3,3,3};
    auto c=compare(a,b,7,100);
    assert(c.difference==2 && c.lower==2 && c.upper==2 && c.distinguishable);
    assert(!compare(a,a,7,100).distinguishable);
    using J=nlohmann::json;
    J header={{"role","client"},{"connections",J::array({{{"index",0},{"warmup",false}}})}};
    std::vector<J> events;
    auto add=[&](const char* kind,int time,const char* call="handshake",int result=0){
        events.push_back({{"kind",kind},{"monotonic_ns",time},{"call",call},{"result",result},
            {"location","implementation_boundary"},{"connection",0}});
    };
    add("CALL_BEGIN",10);add("IO_SEND_ENTER",12);add("IO_SEND_RETURN",15);
    add("CALL_END",20);add("WAIT_BEGIN",21);add("WAIT_END",30);
    add("CALL_BEGIN",31,"app_recv");add("CALL_END",40,"app_recv",2);
    auto p=partition(header,events)[0];
    assert(p["valid"]==true && p["elapsed_ns"]==30);
    assert(p["computation_ns"]==16 && p["io_ns"]==3 && p["wait_ns"]==9 && p["gap_ns"]==2);
    for(auto& e:events) {
        e["thread_cpu_ns"]=e["monotonic_ns"];
        e["cycles"]=2*e["monotonic_ns"].get<unsigned>();
        e["instructions"]=3*e["monotonic_ns"].get<unsigned>();
    }
    header["perf_complete"]=true;
    auto measured=partition(header,events)[0];
    assert(measured["thread_cpu_ns"]==30 && measured["cycles"]==60 && measured["instructions"]==90);
    header["perf_complete"]=false;
    assert(partition(header,events)[0]["cycles"].is_null());
    events.front()["heap"]={{"live",10},{"interval_peak",1000}};
    events.back()["heap"]={{"live",10},{"interval_peak",20}};
    assert(partition(header,events)[0]["heap_peak_bytes"]==20);
    auto kernel=events.front();kernel["location"]="kernel";kernel["monotonic_ns"]=999999;
    events.insert(events.begin()+2,kernel);
    assert(partition(header,events)[0]["elapsed_ns"]==30);
    header.update({{"schema",1},{"type","sample"},{"sample",1},{"batch",1},{"valid",true},
        {"profile_hash","test"},{"environment_hash","env"},{"mode","timing"},
        {"config",J::object()},{"declaration",{{"library","fixture"},{"is_mock",true}}}});
    const auto dir=std::filesystem::temp_directory_path()/("turtle-report-"+std::to_string(getpid()));
    std::filesystem::create_directories(dir);
    {
        std::ofstream raw(dir/"client.jsonl");raw<<header.dump()<<'\n';
        for(const auto& e:events)raw<<e.dump()<<'\n';
    }
    const auto first=summarize(dir/"client.jsonl",dir/"out");
    const auto second=summarize(dir/"client.jsonl",dir/"out");
    assert(first==second && first["groups"].size()==1);
    assert(first["groups"][0]["metrics"]["elapsed_ns"]["stq2"]==30);
    assert(first["groups"][0]["metrics"].contains("cycles")==false);
    assert(std::filesystem::file_size(dir/"out"/"distribution-0.svg")>100);

    const auto fixture_root = std::filesystem::path(__FILE__).parent_path() / "fixtures";
    const auto fixture_dir = dir / "decoded-fixture";
    std::filesystem::create_directory(fixture_dir);
    std::filesystem::copy_file(fixture_root / "client.jsonl", fixture_dir / "client.jsonl");
    std::filesystem::copy_file(fixture_root / "client.decoded.json",
                               fixture_dir / "client.decoded.json");
    const auto decoded_report = summarize(fixture_dir, dir / "decoded-report");
    const auto& alternate = decoded_report["samples"][0]["connections"][0]
                                          ["client_hello_to_finished_send"];
    assert(alternate["start_event_sequence"] == 3);
    assert(alternate["end_event_sequence"] == 8);
    assert(alternate["elapsed_ns"] == 70);
    assert(alternate["thread_cpu_ns"] == 40);
    assert(alternate["cycles"] == 80);
    assert(alternate["client_hello_bundled"] == false);
    assert(alternate["finished_bundled"] == true);
    assert(alternate["separate_plaintext_message_cpu_time_available"] == false);
    assert(decoded_report["groups"][0]["metrics"]
                         ["client_hello_to_finished_send_elapsed_ns"]["stq2"] == 70);
    assert(decoded_report["groups"][0]["client_hello_to_finished_send"]
                         ["separate_plaintext_message_cpu_time_available"] == false);

    const auto raw_only_dir = dir / "raw-only-fixture";
    std::filesystem::create_directory(raw_only_dir);
    std::filesystem::copy_file(fixture_root / "client.jsonl", raw_only_dir / "client.jsonl");
    const auto raw_only = summarize(raw_only_dir, dir / "raw-only-report");
    assert(!raw_only["samples"][0]["connections"][0].contains(
        "client_hello_to_finished_send"));
    assert(raw_only["groups"][0]["metrics"]["elapsed_ns"] ==
           decoded_report["groups"][0]["metrics"]["elapsed_ns"]);

    auto rejected_sidecar = [&](const std::string& name, auto mutate) {
        const auto rejected_dir = dir / name;
        std::filesystem::create_directory(rejected_dir);
        std::filesystem::copy_file(fixture_root / "client.jsonl", rejected_dir / "client.jsonl");
        std::ifstream decoded_fixture(fixture_root / "client.decoded.json");
        auto decoded = J::parse(decoded_fixture);
        mutate(decoded);
        std::ofstream(rejected_dir / "client.decoded.json") << decoded.dump(2) << '\n';
        const auto report = summarize(rejected_dir, dir / (name + "-report"));
        assert(!report["samples"][0]["connections"][0].contains(
            "client_hello_to_finished_send"));
    };
    rejected_sidecar("mismatched-sample", [](J& decoded) { decoded["sample"] = 999; });
    rejected_sidecar("mismatched-role", [](J& decoded) { decoded["role"] = "server"; });
    rejected_sidecar("mismatched-connection",
                     [](J& decoded) { decoded["connections"][0]["connection"] = 1; });
    rejected_sidecar("incomplete-decode",
                     [](J& decoded) { decoded["connections"][0]["decryption_complete"] = false; });
    for(int i=0;i<4;++i) {
        auto alternate=header;
        if(i==0)alternate["config"]["server_adapter"]="different_peer";
        if(i==1)alternate["pinned_cpu"]=3;
        if(i==2)alternate["config"]["perf"]=true;
        if(i==3)alternate["declaration"]["build_options"]="different_build";
        auto folder=dir/std::to_string(i);
        std::filesystem::create_directory(folder);
        std::ofstream raw(folder/"client.jsonl");raw<<alternate.dump()<<'\n';
        for(const auto& e:events)raw<<e.dump()<<'\n';
    }
    const auto separated=summarize(dir,dir/"grouped");
    assert(separated["groups"].size()>=5);

    const auto candidates_dir = dir / "comparison-candidates";
    std::filesystem::create_directory(candidates_dir);
    auto write_candidate = [&](const std::string& folder_name, const std::string& own_adapter,
                               const std::string& peer_adapter, const std::string& profile,
                               const std::string& library) {
        auto candidate = header;
        candidate["config"]["client_adapter"] = own_adapter;
        candidate["config"]["server_adapter"] = peer_adapter;
        candidate["profile_hash"] = profile;
        candidate["declaration"]["library"] = library;
        candidate["declaration"]["version"] = library + "-version";
        candidate["declaration"]["build_options"] = library + "-build";
        const auto folder = candidates_dir / folder_name;
        std::filesystem::create_directory(folder);
        std::ofstream raw(folder / "client.jsonl");
        raw << candidate.dump() << '\n';
        for (const auto& event : events) {
            raw << event.dump() << '\n';
        }
    };
    write_candidate("a", "adapter-a", "fixed-peer", "same-profile", "library-a");
    write_candidate("b", "adapter-b", "fixed-peer", "same-profile", "library-b");
    write_candidate("different-peer", "adapter-c", "other-peer", "same-profile", "library-c");
    write_candidate("different-profile", "adapter-d", "fixed-peer", "other-profile",
                    "library-d");
    const auto candidates = summarize(candidates_dir, dir / "candidate-report");
    assert(candidates["groups"].size() == 4);
    assert(candidates["comparisons"].size() == 1);
    assert(candidates["comparisons"][0]["method"] == "independent_percentile_bootstrap");
    assert(candidates["comparisons"][0]["interpretation"] ==
           "exploratory_adapter_candidate_not_equivalence");
    assert(candidates["comparisons"][0]["eligibility"] ==
           "same_conditions_and_fixed_peer_except_measured_adapter_identity");
    std::filesystem::remove_all(dir);
    std::cout<<"report tests passed\n";
}
