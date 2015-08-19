#ifndef VAST_UTIL_IDENTITY_H
#define VAST_UTIL_IDENTITY_H

#include <utility>

namespace vast {
namespace util {

/// A function object that acts as identity function.
struct identity {
  template <typename T>
  constexpr auto operator()(T&& x) const noexcept
    -> decltype(std::forward<T>(x)) {
    return std::forward<T>(x);
  }
};

} // namespace util
} // namespace vast

#endif
