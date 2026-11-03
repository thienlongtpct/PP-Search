#pragma once

// The pp_client subcommands. Each prints one JSON object on stdout and returns
// the process exit code.

#include "common/arguments.hpp"

namespace pps::client {

int run_requester(const Arguments& arguments);
int run_station(const Arguments& arguments);
int run_stations(const Arguments& arguments);
int run_coordinator(const Arguments& arguments);
int run_fault_injection(const Arguments& arguments);  // tests only
int run_unchecked_station(const Arguments& arguments);  // tests only

}  // namespace pps::client
