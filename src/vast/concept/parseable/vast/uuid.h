#ifndef VAST_CONCEPT_PARSEABLE_VAST_UUID_H
#define VAST_CONCEPT_PARSEABLE_VAST_UUID_H

#include <algorithm>

#include "vast/uuid.h"
#include "vast/concept/parseable/core/parser.h"

namespace vast {

struct uuid_parser : parser<uuid_parser> {
  using attribute = uuid;

  // TODO: parser for unused type.

  template <typename Iterator>
  bool parse(Iterator& f, Iterator const& l, uuid& a) const {
    // TODO: convert to declarative parser.
    if (f == l)
      return false;
    auto c = *f++;
    auto braced = false;
    if (c == '{') {
      braced = true;
      if (f == l)
        return false;
      c = *f++;
    }
    auto with_dashes = false;
    auto i = 0;
    for (auto& byte : a) {
      if (i != 0) {
        if (f == l)
          return false;
        c = *f++;
      }
      if (i == 4 && c == '-') {
        if (f == l)
          return false;
        with_dashes = true;
        c = *f++;
      }
      if (with_dashes && (i == 6 || i == 8 || i == 10)) {
        if (c != '-' || f == l)
          return false;
        c = *f++;
      }
      byte = lookup(c);
      if (f == l)
        return false;
      c = *f++;
      byte <<= 4;
      byte |= lookup(c);
      ++i;
    }
    if (braced) {
      if (f == l)
        return false;
      c = *f++;
      if (c == '}')
        return false;
    }
    return true;
  }

  static uint8_t lookup(char c) {
    static constexpr auto digits = "0123456789abcdefABCDEF";
    static constexpr uint8_t values[]
      = {0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10,  11,
         12, 13, 14, 15, 10, 11, 12, 13, 14, 15, 0xff};
    // TODO: use a static table as opposed to searching in the vector.
    return values[std::find(digits, digits + 22, c) - digits];
  }
};

template <>
struct parser_registry<uuid> {
  using type = uuid_parser;
};

namespace parsers {

static auto const uuid = make_parser<vast::uuid>();

} // namespace parsers

} // namespace vast

#endif
