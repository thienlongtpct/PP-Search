#pragma once

#include "common/deadline.hpp"

#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <string>
#include <thread>

namespace pps {

// Terminates the process if the MPC phase outlives its bound; MP-SPDZ state
// after a stalled peer cannot be resumed safely (fail-stop, no output).
class Watchdog {
public:
    Watchdog(Clock::time_point deadline, std::string label) {
        thread_ = std::thread([this, deadline, label] {
            std::unique_lock<std::mutex> lock(mutex_);
            if (!condition_.wait_until(lock, deadline, [this] { return done_; })) {
                std::fprintf(stderr, "%s: MPC watchdog expired; terminating without output\n",
                             label.c_str());
                std::fflush(stderr);
                std::_Exit(4);
            }
        });
    }
    ~Watchdog() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            done_ = true;
        }
        condition_.notify_all();
        thread_.join();
    }

private:
    std::mutex mutex_;
    std::condition_variable condition_;
    bool done_ = false;
    std::thread thread_;
};

}  // namespace pps
