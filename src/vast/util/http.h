#ifndef VAST_UTIL_HTTP
#define VAST_UTIL_HTTP

#include <map>
#include <string>
#include <vector>

#include "vast/none.h"
#include "vast/concept/printable/to.h"
#include "vast/util/operators.h"
#include "vast/util/variant.h"

namespace vast {
namespace util {

/// A http_request data type.
class http_request
{
public:

  http_request() = default;

  http_request(std::string method, std::string url, std::string http_version)
    : method_(method),
	  url_(url),
	  http_version_(http_version)
  {
  }

  std::string Method()
  {
    return method_;
  }

  std::string URL()
  {
    return url_;
  }

  std::string HTTP_version()
  {
    return http_version_;
  }

  std::map<std::string, std::string> Header()
  {
    return header_;
  }

  std::string Header(std::string key)
  {
    return header_[key];
  }
  
  std::string Body()
  {
    return body_;
  }
  
  void set_Body(std::string body)
  {
    body_ = body;
  }

  void add_header_field(std::string key, std::string value)
  {
    header_[key] = value;
  }

private:
  std::string method_;
  std::string url_;
  std::string http_version_;
  std::map<std::string, std::string> header_;
  std::string body_;

};

/// A http_respnse data type.
class http_response
{
public:

  http_response(){
    http_version_ = "HTTP/1.1";
    status_code_ = 200;
    status_text_ = "OK";
  }

  std::string HTTP_version() const
  {
    return http_version_;
  }
  
  void set_HTTP_version(std::string http_version)
  {
    http_version_ = http_version;
  }
  
  uint32_t status_code() const
  {
    return status_code_;
  }
  
  void set_status_code(uint32_t status_code)
  {
    status_code_ = status_code;
  }
  
  std::string status_text() const
  {
    return status_text_;
  }
  
  void set_status_text(std::string status_text)
  {
    status_text_ = status_text;
  }
  
  std::map<std::string, std::string> Header() const
  {
    return header_;
  }

  std::string Header(std::string key)
  {
    return header_[key];
  }
  
  std::string Body() const
  {
    return body_;
  }
  
  void set_Body(std::string body)
  {
    body_ = body;
  }

  void add_header_field(std::string key, std::string value)
  {
    header_[key] = value;
  }

private:
  std::string http_version_;
  uint32_t status_code_;
  std::string status_text_;
  std::map<std::string, std::string> header_;
  std::string body_;

};

/// A http_url data type.
class http_url
{
public:


  /// Default-constructs a null JSON value.
  http_url() = default;

  std::vector<std::string> Path()
  {
    return path_;
  }

  void add_path_segment(std::string path_segment)
  {
	  path_.push_back(path_segment);
  }

  std::map<std::string, std::string> Options()
  {
    return options_;
  }

  std::string Options(std::string key)
  {
    return options_[key];
  }

  void add_option(std::string key, std::string value)
  {
	  options_[key] = value;
  }

  bool contains_option(std::string key)
  {
    return options_.count(key) > 0;
    //if (options_.find(key) != options_.end())
    //{
    //  return true;
    //}
    //return false;
  }

private:
  std::vector<std::string> path_;
  std::map<std::string, std::string> options_;

};


} // namespace util
} // namespace vast

#endif
