#pragma once

#include "common/deadline.hpp"

namespace pps {

inline constexpr Millis kHandshakeTimeout{5000};
inline constexpr Millis kControlTimeout{10000};

}  // namespace pps
