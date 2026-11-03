// pp_client: coordinator, requester and station roles.
//
//   pp_client new-session
//   pp_client coordinator --pki DIR --party0 H:P --party1 H:P --session HEX
//             --horizon D --requester NAME
//             (--stations ID,ID,... | --stations-file FILE) [--timeout-ms MS]
//             [--result-timeout-ms MS]
//   pp_client requester --pki DIR --party0 H:P --party1 H:P --session HEX
//             --name NAME --x X --y Y [--timeout-ms MS]
//   pp_client station --pki DIR --party0 H:P --party1 H:P --session HEX
//             --id ID --x X --y Y --radius R [--timeout-ms MS]
//   pp_client stations --pki DIR --party0 H:P --party1 H:P --session HEX
//             --file CSV(id,x,y,radius) [--timeout-ms MS]
//
// Every command prints one JSON object on stdout. Input owners split each
// value into two fresh uniformly random additive shares modulo 2^128 and send
// exactly one share to each party over its own mutually authenticated TLS
// connection.

#include "client/commands.hpp"
#include "net/tls_transport.hpp"
#include "net/wire.hpp"

#include <csignal>
#include <iostream>
#include <stdexcept>
#include <string>

int main(int argc, char** argv) {
    std::signal(SIGPIPE, SIG_IGN);
    pps::raise_file_descriptor_limit();
    if (argc < 2) {
        std::cerr << "usage: pp_client <new-session|coordinator|requester|station|stations> [options]\n";
        return 64;
    }
    const std::string command = argv[1];
    try {
        if (command == "new-session") {
            std::cout << pps::wire::session_hex(pps::wire::random_session_id()) << std::endl;
            return 0;
        }
        const pps::Arguments arguments(argc, argv, 2);
        if (command == "coordinator") return pps::client::run_coordinator(arguments);
        if (command == "requester") return pps::client::run_requester(arguments);
        if (command == "station") return pps::client::run_station(arguments);
        if (command == "stations") return pps::client::run_stations(arguments);
        if (command == "test-inject") return pps::client::run_fault_injection(arguments);
        if (command == "test-unchecked-station") return pps::client::run_unchecked_station(arguments);
        throw std::invalid_argument("unknown command " + command);
    } catch (const std::invalid_argument& error) {
        std::cerr << "error: " << error.what() << "\n";
        return 64;
    } catch (const std::out_of_range& error) {
        std::cerr << "error: " << error.what() << "\n";
        return 64;
    } catch (const std::exception& error) {
        std::cerr << "fatal: " << error.what() << "\n";
        return 1;
    }
}
