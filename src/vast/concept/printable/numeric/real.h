#ifndef VAST_CONCEPT_PRINTABLE_NUMERIC_REAL_H
#define VAST_CONCEPT_PRINTABLE_NUMERIC_REAL_H

#include <cmath>
#include <cstdint>
#include <string>
#include <type_traits>

#include "vast/concept/printable/detail/print_numeric.h"
#include "vast/concept/printable/core/printer.h"

namespace vast {

template <typename T, int Digits = 10>
struct real_printer : printer<real_printer<T, Digits>> {
  static_assert(std::is_floating_point<T>{}, "T must be a floating point type");

  using attribute = T;

  template <typename Iterator>
  bool print(Iterator& out, T x) const {
    // if (Digits < 0)
    //  // FIXME: Improve performance by not going through std::string.
    //  return print(out, std::to_string(x));
    if (x == 0) {
      *out++ = '0';
      *out++ = '.';
      for (auto i = 0; i < Digits; ++i)
        *out++ = '0';
      return true;
    }
    if (x < 0) {
      *out++ = '-';
      x = -x;
    }
    T left;
    uint64_t right = std::round(std::modf(x, &left) * std::pow(10, Digits));
    if (Digits == 0)
      return detail::print_numeric(out, static_cast<uint64_t>(std::round(x)));
    if (!detail::print_numeric(out, static_cast<uint64_t>(left)))
      return false;
    *out++ = '.';
    auto magnitude = right == 0 ? 0 : std::log10(right);
    for (auto i = 1.0; i < Digits - magnitude; ++i)
      *out++ = '0';
    return detail::print_numeric(out, right);
  }
};

template <typename T>
struct printer_registry<T, std::enable_if_t<std::is_floating_point<T>::value>> {
  using type = real_printer<T>;
};

namespace printers {

auto const fp = real_printer<float>{};
auto const real = real_printer<double>{};

} // namespace printers
} // namespace vast

#endif
