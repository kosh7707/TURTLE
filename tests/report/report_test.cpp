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
    std::filesystem::remove_all(dir);
    std::cout<<"report tests passed\n";
}
