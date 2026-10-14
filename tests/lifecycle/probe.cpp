#define turtle_adapter_v1 turtle_mock_api
#include "../../implementations/mock/mock.cpp"
#undef turtle_adapter_v1
#include "transport/tcp.hpp"
#include <sys/resource.h>
namespace {
turtle::Context* checked_setup(turtle::Role role,const turtle::TlsConfig& config,const turtle::HostServices& host,std::span<const std::uint8_t> saved) {
 rlimit limit{};
 if(::getrlimit(RLIMIT_NOFILE,&limit)||limit.rlim_cur==0)return nullptr;
 return turtle_mock_api().setup(role,config,host,saved);
}
turtle::Connection* checked_open(turtle::Context* context,const turtle::Io& io) {
 rlimit limit{};
 if(::getrlimit(RLIMIT_NOFILE,&limit)||limit.rlim_cur!=0)return nullptr;
 // Every open must receive a fresh, established and still empty TCP stream.
 if(!turtle::tcp::check_ready(io.native_socket).empty())return nullptr;
 return turtle_mock_api().open(context,io);
}
}
extern "C" turtle::ImplementationApi turtle_adapter_v1() {
 auto api=turtle_mock_api();api.setup=checked_setup;api.open=checked_open;return api;
}
