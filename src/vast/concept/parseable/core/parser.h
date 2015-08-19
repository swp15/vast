#ifndef VAST_CONCEPT_PARSEABLE_CORE_PARSER_H
#define VAST_CONCEPT_PARSEABLE_CORE_PARSER_H

#include <type_traits>
#include <iterator>

#include "vast/concept/support/unused_type.h"

namespace vast {

template <typename, typename>
class action_parser;

template <typename, typename>
class guard_parser;

template <typename Derived>
struct parser {
  template <typename Action>
  auto then(Action fun) const {
    return action_parser<Derived, Action>{derived(), fun};
  }

  template <typename Action>
  auto operator->*(Action fun) const {
    return then(fun);
  }

  template <typename Guard>
  auto with(Guard fun) const {
    return guard_parser<Derived, Guard>{derived(), fun};
  }

  template <typename Range, typename Attribute = unused_type>
  bool operator()(Range&& r, Attribute& a = unused) const {
    using std::begin;
    using std::end;
    auto f = begin(r);
    auto l = end(r);
    return derived().parse(f, l, a);
  }

private:
  Derived const& derived() const {
    return static_cast<Derived const&>(*this);
  }
};

/// Associates a parser for a given type. To register a parser with a type, one
/// needs to specialize this struct and expose a member `type` with the
/// concrete parser type.
/// @tparam T the type to register a parser with.
template <typename T, typename = void>
struct parser_registry;

/// Retrieves a registered parser.
template <typename T>
using make_parser = typename parser_registry<T>::type;

namespace detail {

struct has_parser {
  template <typename T>
  static auto test(T*) -> std::is_class<typename parser_registry<T>::type>;

  template <typename>
  static auto test(...) -> std::false_type;
};

} // namespace detail

/// Checks whether the parser registry has a given type registered.
template <typename T>
struct has_parser : decltype(detail::has_parser::test<T>(0)) {};

/// Checks whether a given type is-a parser, i.e., derived from ::vast::parser.
template <typename T>
using is_parser = std::is_base_of<parser<T>, T>;

} // namespace vast

#endif
