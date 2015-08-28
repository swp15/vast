#ifndef VAST_CONCEPT_PARSEABLE_VAST_HTTP_H
#define VAST_CONCEPT_PARSEABLE_VAST_HTTP_H

#include <string>
#include "vast/concept/parseable/core.h"
#include "vast/concept/parseable/string.h"
#include "vast/util/http.h"
#include "vast/util/string.h"


namespace vast {

class http_parser : public parser<http_parser>
{
public:
  using attribute = util::http_request;

  http_parser()
  {
  }

  static auto make()
  {
    auto sp = ignore(parsers::space);
    auto crlf = ignore(parsers::str{"\r\n"});
    auto method = +(parsers::print - sp);
    auto uri = +(parsers::print - sp);
    auto protocol = +(parsers::print - sp);
    auto first_line = method >> sp >> uri >> sp >> protocol >> crlf;
    auto header_field = +(print_parser{} - ':') >> ':' >> +(print_parser{} - crlf) >> crlf;
    auto header = *(header_field);
    auto body = *(parsers::print);
    return method >> sp >> uri >> sp >> protocol >> crlf >> header >> crlf >> body;
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
    static auto p = make();
    using std::get;
    std::tuple<std::string,std::string,std::string,std::vector<std::tuple<std::string,std::string>>,std::string> h;
    if (p.parse(f, l, h))
    {
      util::http_request request(get<0>(h),get<1>(h),get<2>(h));
      for (auto& header_field : get<3>(h))
      {
        auto key = get<0>(header_field);
        auto value = get<1>(header_field);
        request.add_header_field(key,value);
      }
      request.set_Body(get<4>(h));
      a = request;
      return true;
    }
    return false;
  }

};

template <>
struct parser_registry<util::http_request>
{
  using type = http_parser;
};


class url_parser : public parser<url_parser>
{
public:
  using attribute = util::http_url;

  url_parser()
  {
  }

  static auto make()
  {
    auto path_ignor_char = ignore(char_parser{'/'}) | ignore(char_parser{'?'});
    auto path_char = print_parser{} - path_ignor_char;
    auto path_segments =  '/' >> (*(path_char)) % '/';
    auto option_key = +(print_parser{} - '=');
    auto option_value = +(print_parser{} - '&');
    auto option = option_key >> '=' >> option_value;
    auto options = option % '&';
    return path_segments >> -('?' >> options);
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
    static auto p = make();
    using std::get;
    std::tuple<std::vector<std::string>,optional<std::vector<std::tuple<std::string,std::string>>>> h;
    if (p.parse(f, l, h))
    {
      util::http_url url;
      for (auto& path_segments : get<0>(h)){
        url.add_path_segment(path_segments);
      }
      if (get<1>(h))
      {
        for (auto& option : *get<1>(h)){
          std::string key = get<0>(option);
          std::string value = get<1>(option);
          key = util::url_unescape(key);
          value = util::url_unescape(value);
          url.add_option(key, value);
        }
      }
      a = url;
      return true;
    }
    return false;
  }

};

template <>
struct parser_registry<util::http_url>
{
  using type = url_parser;
};

} // namespace vast

#endif
