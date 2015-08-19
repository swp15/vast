#include "vast/util/string.h"

#define SUITE util
#include "test.h"

using namespace vast;
using namespace util;

TEST(string byte escaping) {
  // Identities.
  CHECK(byte_escape("") == "");
  CHECK(byte_escape("foo") == "foo");
  CHECK(byte_escape("foo bar") == "foo bar");

  CHECK(byte_escape("foobar", "o") == "f\\o\\obar");

  CHECK(byte_escape("foob\ar") == "foob\\x07r");
  CHECK(byte_escape("foo\tbar") == "foo\\x09bar");
  CHECK(byte_escape("foo\nbar") == "foo\\x0abar");
  CHECK(byte_escape("foo\r\nbar") == "foo\\x0d\\x0abar");

  CHECK(byte_unescape("f\\o\\obar") == "foobar");

  CHECK(byte_unescape("foob\\x07r") == "foob\ar");
  CHECK(byte_unescape("foo\\x09bar") == "foo\tbar");
  CHECK(byte_unescape("foo\\x0abar") == "foo\nbar");
  CHECK(byte_unescape("foo\\x0d\\x0abar") == "foo\r\nbar");

  CHECK(byte_escape_all("foo") == "\\x66\\x6f\\x6f");
  CHECK(byte_unescape("\\x66\\x6f\\x6f") == "foo");

  CHECK(byte_unescape("foo\\") == ""); // Invalid '/' at end of string.
}

TEST(JSON string escaping) {
  CHECK(json_escape("") == "\"\"");
  CHECK(json_escape("\r") == "\"\\r\"");
  CHECK(json_escape("\r\n") == "\"\\r\\n\"");
  CHECK(json_escape("\begin") == "\"\\begin\"");
  CHECK(json_escape("end\n") == "\"end\\n\"");

  CHECK(json_unescape("\"\"") == "");
  CHECK(json_unescape("\"\\r\"") == "\r");
  CHECK(json_unescape("\"\\r\\n\"") == "\r\n");
  CHECK(json_unescape("\"\\begin\"") == "\begin");
  CHECK(json_unescape("\"end\\n\"") == "end\n");
  CHECK(json_unescape("\"end\\uaaaa\"") == "end\\uaaaa");

  CHECK(json_escape("foo\"bar") == "\"foo\\\"bar\"");
  CHECK(json_escape("foo\\bar") == "\"foo\\\\bar\"");
  CHECK(json_escape("foo\bbar") == "\"foo\\bbar\"");
  CHECK(json_escape("foo\fbar") == "\"foo\\fbar\"");
  CHECK(json_escape("foo\rbar") == "\"foo\\rbar\"");
  CHECK(json_escape("foo\nbar") == "\"foo\\nbar\"");
  CHECK(json_escape("foo\tbar") == "\"foo\\tbar\"");
  CHECK(json_escape("foo\xFF\xFF") == "\"foo\\xff\\xff\"");

  CHECK(json_unescape("\"foo\\\"bar\"") == "foo\"bar");
  CHECK(json_unescape("\"foo\\\\bar\"") == "foo\\bar");
  CHECK(json_unescape("\"foo\\/bar\"")  == "foo/bar");
  CHECK(json_unescape("\"foo\\bbar\"")  == "foo\bbar");
  CHECK(json_unescape("\"foo\\fbar\"")  == "foo\fbar");
  CHECK(json_unescape("\"foo\\rbar\"")  == "foo\rbar");
  CHECK(json_unescape("\"foo\\nbar\"")  == "foo\nbar");
  CHECK(json_unescape("\"foo\\tbar\"")  == "foo\tbar");
  CHECK(json_unescape("\"foo\\uaaaabar\"")  == "foo\\uaaaabar");
  CHECK(json_unescape("\"foo\\xFF\\xFF\"") == "foo\xFF\xFF");

  // Invalid.
  CHECK(json_unescape("unquoted") == "");
  CHECK(json_unescape("\"") == "");
  CHECK(json_unescape("\"invalid \\x escape sequence\"") == "");
  CHECK(json_unescape("\"unescaped\"quote\"") == "");
}

TEST(string splitting and joining) {
  using namespace std::string_literals;

  auto s = split_to_str("Der Geist, der stets verneint."s, " ");
  REQUIRE(s.size() == 5);
  CHECK(s[0] == "Der");
  CHECK(s[1] == "Geist,");
  CHECK(s[2] == "der");
  CHECK(s[3] == "stets");
  CHECK(s[4] == "verneint.");

  s = split_to_str("foo"s, "x");
  REQUIRE(s.size() == 1);
  CHECK(s[0] == "foo");

  // TODO: it would be more consistent if split considered not only before the
  // first seperator, but also after the last one. But this is not how many
  // split implementations operate.
  s = split_to_str(",,"s, ",");
  REQUIRE(s.size() == 2);
  CHECK(s[0] == "");
  CHECK(s[1] == "");

  s = split_to_str(",a,b,c,"s, ",");
  REQUIRE(s.size() == 4);
  CHECK(s[0] == "");
  CHECK(s[1] == "a");
  CHECK(s[2] == "b");
  CHECK(s[3] == "c");

  s = split_to_str("a*,b,c"s, ",", "*");
  REQUIRE(s.size() == 2);
  CHECK(s[0] == "a*,b");
  CHECK(s[1] == "c");

  s = split_to_str("a,b,c,d,e,f"s, ",", "", 1);
  REQUIRE(s.size() == 2);
  CHECK(s[0] == "a");
  CHECK(s[1] == "b,c,d,e,f");

  s = split_to_str("a-b-c*-d"s, "-", "*", -1, true);
  REQUIRE(s.size() == 5);
  CHECK(s[0] == "a");
  CHECK(s[1] == "-");
  CHECK(s[2] == "b");
  CHECK(s[3] == "-");
  CHECK(s[4] == "c*-d");

  auto str = join(s, "");
  CHECK(str == "a-b-c*-d");
  str = join(s, " ");
  CHECK(str == "a - b - c*-d");
}
