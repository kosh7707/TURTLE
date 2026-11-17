#include "implementation.hpp"
#include <turtle/endpoint.h>
int main(int argc, char** argv) {
    const auto api = turtle_wolfssl::implementation();
    return turtle_endpoint_main(&api, argc, argv);
}
