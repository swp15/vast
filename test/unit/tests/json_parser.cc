#include "vast/data.h"
#include "vast/util/json.h"
#include "vast/concept/parseable/core.h"
#include "vast/concept/parseable/vast/json.h"

#define SUITE json_parse
#include "test.h"

using namespace vast;

TEST(util::json)
{
  auto pt = make_parser<util::json>{};
  auto str = std::string{"[true,false,true,true]"};
  auto f = str.begin();
  auto l = str.end();
  util::json j;
  CHECK(pt.parse(f, l, j));
  std::cout << j;
  CHECK(f == l);
}

