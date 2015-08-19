#ifndef VAST_EXPR_RESTRICTOR_H
#define VAST_EXPR_RESTRICTOR_H

#include "vast/none.h"
#include "vast/time.h"

namespace vast {

class expression;
struct conjunction;
struct disjunction;
struct negation;
struct predicate;

namespace expr {

/// Checks whether an expression is valid for a given time interval. The
/// visitor returns `false` if a time extractor restricts all predicates to lay
/// outside the given interval, and returns `true` if at least one unrestricted
/// predicate exists in the expression.
struct time_restrictor {
  time_restrictor(time::point first, time::point second);

  bool operator()(none) const;
  bool operator()(conjunction const& con) const;
  bool operator()(disjunction const& dis) const;
  bool operator()(negation const& n) const;
  bool operator()(predicate const& p) const;

  time::point first_;
  time::point last_;
};

} // namespace expr
} // namespace vast

#endif
