#pragma once

#include <turtle/endpoint.h>

extern "C" turtle_result turtle_observe_run_submission_endpoint(
    const turtle_endpoint *endpoint,
    turtle_result (*accept_greeting)(void *, const void *, size_t));
