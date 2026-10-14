#include "report/report.hpp"
#include <iostream>
int main(int argc,char** argv) {
    try {
        if(argc!=3){std::cerr<<"usage: turtle-report INPUT_FILE_OR_DIRECTORY OUTPUT_DIRECTORY\n";return 2;}
        const auto r=turtle::report::summarize(argv[1],argv[2]);
        std::cout<<r.at("groups").size()<<" groups, "<<r.at("invalid_samples")<<" invalid samples\n";
        return 0;
    }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
}
