#include "lifecycle/lifecycle.hpp"
#include <nlohmann/json.hpp>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <unistd.h>
int main(int argc,char** argv) {
 if(argc<3||argc>5)return 2;
 const auto root=std::filesystem::temp_directory_path()/("turtle-real-runtime-"+std::to_string(::getpid()));
 try {
  turtle::model::RunConfig config;config.adapter_directory=argv[1];config.client_adapter=argc>3?argv[3]:"openssl";config.server_adapter=argc>4?argv[4]:config.client_adapter;
  config.samples=2;config.warmups=1;config.perf=false;config.calibration_samples=2;
  auto pki=std::filesystem::absolute(argv[2]);
  config.tls.ca_file=(pki/"ca.pem").string();config.tls.server_certificate=(pki/"server-chain.pem").string();config.tls.server_key=(pki/"server.key").string();
  config.tls.client_certificate=(pki/"client-chain.pem").string();config.tls.client_key=(pki/"client.key").string();
  for(bool mutual:{false,true})for(auto mode:{turtle::model::Mode::Timing,turtle::model::Mode::Memory}) {
   config.tls.mutual_auth=mutual;config.mode=mode;
   config.output_directory=(root/(std::string(mutual?"mutual-":"server-")+turtle::model::name(mode))).string();
   if(turtle::lifecycle::run(config))throw std::runtime_error("TLS runtime failed");
   for(const char* sample:{"sample-000001","sample-000002"})for(const char* role:{"client","server"}) {
    std::ifstream in(std::filesystem::path(config.output_directory)/sample/(std::string(role)+".jsonl"));std::string line;std::getline(in,line);auto data=nlohmann::json::parse(line);
    if(!data.at("valid").get<bool>()||data.at("declaration").at("is_mock").get<bool>())throw std::runtime_error("not a valid real TLS sample");
    for(const auto& c:data.at("connections"))if(c.at("negotiated").at("version")!="TLS1.3"||!c.at("application_verified").get<bool>())throw std::runtime_error("TLS or application result missing");
   }
  }
  std::cout<<"real TLS runtime passed: "<<root<<'\n';
 }catch(const std::exception& e){std::cerr<<e.what()<<" (artifacts: "<<root<<")\n";return 1;}
}
