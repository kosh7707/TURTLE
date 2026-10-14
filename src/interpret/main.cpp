#include "interpret/interpret.hpp"
#include <iostream>
int main(int argc,char** argv) {
    try {
        if(argc!=3){std::cerr<<"usage: turtle-interpret ROLE_JSONL OUTPUT_JSON\n";return 2;}
        turtle::interpret::analyze(argv[1],argv[2]);return 0;
    }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
}
