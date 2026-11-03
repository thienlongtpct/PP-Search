#pragma once

#include <stdexcept>
#include <string>

#define CHECK(condition) \
    do { \
        if (!(condition)) { \
            throw std::runtime_error("check failed: " #condition); \
        } \
    } while (false)

template <class Exception, class Function>
void expect_throw(Function function, const char* what) {
    bool thrown = false;
    try {
        function();
    } catch (const Exception&) {
        thrown = true;
    }
    if (!thrown) {
        throw std::runtime_error(std::string("expected exception: ") + what);
    }
}
