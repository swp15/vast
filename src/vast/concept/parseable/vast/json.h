#ifndef VAST_CONCEPT_PARSEABLE_VAST_JSON_H
#define VAST_CONCEPT_PARSEABLE_VAST_JSON_H

#include <map>
#include <string>
#include <vector>
#include "vast/util/json.h"
#include "vast/access.h"
#include "vast/concept/parseable/core/and.h"
#include "vast/concept/parseable/core/or.h"
#include "vast/concept/parseable/core/optional.h"
#include "vast/concept/parseable/core/kleene.h"
#include "vast/concept/parseable/numeric/bool.h"
#include "vast/concept/parseable/numeric/real.h"
#include "vast/concept/parseable/numeric/integral.h"
#include "vast/concept/parseable/string.h"


namespace vast {

using namespace vast::util;

struct json_parser : parser<json_parser>
{
  using attribute = json;

  static auto make()
  {
    //auto string = char_parser{'"'} >> string >> char_parser{'"'};
    //auto number = real_parser{} | integral_parser{};
    //auto value = string | number | object | array | literal_bool_parser{} | string_parser{"null"};
    auto value = literal_bool_parser{};
    //auto pair = string >> char_parser{':'} >> value;
    //auto members = pair >> *(char_parser{','} >> pair);
    //auto object = char_parser{'{'} >> members >> char_parser{'}'};
    auto elements = value >> *(char_parser{','} >> value);
    auto array = char_parser{'['} >> ~(elements) >> char_parser{']'};
    return array;
  }


  template <typename Iterator>
  bool parse(Iterator& f, Iterator const& l, unused_type) const
  {
    static auto p = make();
    return p.parse(f, l, unused);
  }


  template <typename Iterator, typename Attribute>
  bool parse(Iterator& f, Iterator const& l, Attribute& a) const
  {
    using std::get;
    static auto p = make();
    auto j = decltype(p)::attribute{};
    if (p.parse(f, l, j))
    {
      if (get<1>(j))//array
      {
        auto elements = get<1>(j).get();

        json::array arr;
        json i;
        auto t = convert(get<0>(elements), i);
        arr.push_back(std::move(i));
        for (auto& x : get<1>(elements))
        {
          //json i;
          auto t = convert(get<1>(x), i);
          if (! t)
            return false;
          arr.push_back(std::move(i));
        };

        a = arr;

      }
      return true;
    }
    return false;
  }
};

template <>
struct parser_registry<json>
{
  using type = json_parser;
};



} // namespace vast

#endif
