#ifndef VAST_CONCEPT_PRINTABLE_VAST_HTTP_H
#define VAST_CONCEPT_PRINTABLE_VAST_HTTP_H

#include <string>
#include "vast/util/http.h"
#include "vast/concept/printable/core/printer.h"
#include "vast/concept/printable/numeric/integral.h"
#include "vast/concept/printable/string/any.h"

namespace vast {

struct http_response_printer : printer<http_response_printer> {
  using attribute = util::http_response;
  
  std::string header_to_string(std::map<std::string, std::string> header) const {
    std::string txt = "";
    for (auto& kv : header){
      txt += kv.first;
      txt += ":";
      txt += kv.second;
      txt += "\r\n";
    }
    return txt;
  }

  template <typename Iterator>
  bool print(Iterator& out, util::http_response const& response) const {
    using namespace printers;
    return str.print(out, response.HTTP_version()) && any.print(out, ' ')
           && u32.print(out, response.status_code()) && any.print(out, ' ')
           && str.print(out, response.status_text()) && str.print(out, "\r\n")
           && str.print(out, header_to_string(response.Header())) && str.print(out, "\r\n")
           && str.print(out, response.Body());
  }
};

template <>
struct printer_registry<util::http_response> {
  using type = http_response_printer;
};

} // namespace vast

#endif
