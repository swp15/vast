#ifndef VAST_CONCEPT_PRINTABLE_STRING_STRING_H
#define VAST_CONCEPT_PRINTABLE_STRING_STRING_H

#include "vast/concept/printable/core/printer.h"
#include "vast/concept/printable/string/any.h"

namespace vast {

struct string_printer : printer<string_printer> {
  using attribute = std::string;

  template <typename Iterator, typename StringIterator>
  static bool print_string(Iterator& out, StringIterator f, StringIterator l) {
    while (f != l)
      if (!printers::any.print(out, *f++))
        return false;
    return true;
  }

  template <typename Iterator>
  static bool print_string(Iterator& out, char const* str) {
    while (*str != '\0')
      if (!printers::any.print(out, *str++))
        return false;
    return true;
  }

  template <typename Iterator>
  static bool print_string(Iterator& out, std::string const& str) {
    return print_string(out, str.begin(), str.end());
  }

  template <typename Iterator, size_t N>
  static bool print(Iterator& out, const char(&str)[N]) {
    return print_string(out, str, str + N - 1); // without the last NUL byte.
  }

  template <typename Iterator, typename Attribute>
  bool print(Iterator& out, Attribute const& str) const {
    return print_string(out, str);
  }
};

template <size_t N>
struct printer_registry<const char(&)[N]> {
  using type = string_printer;
};

template <size_t N>
struct printer_registry<char[N]> {
  using type = string_printer;
};

template <>
struct printer_registry<char const*> {
  using type = string_printer;
};

template <>
struct printer_registry<char*> {
  using type = string_printer;
};

template <>
struct printer_registry<std::string> {
  using type = string_printer;
};

namespace printers {

auto const str = string_printer{};

} // namespace printers
} // namespace vast

#endif
