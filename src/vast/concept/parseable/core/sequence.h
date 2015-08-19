#ifndef VAST_CONCEPT_PARSEABLE_CORE_SEQUENCE_H
#define VAST_CONCEPT_PARSEABLE_CORE_SEQUENCE_H

#include <tuple>
#include <type_traits>

#include "vast/concept/parseable/core/parser.h"

namespace vast {

template <typename Lhs, typename Rhs>
class sequence_parser;

template <typename>
struct is_tuple : std::false_type {};

template <typename... Ts>
struct is_tuple<std::tuple<Ts...>> : std::true_type {};

template <typename T>
using tuple_wrap = std::conditional_t<is_tuple<T>::value, T, std::tuple<T>>;

template <typename>
struct is_sequence_parser : std::false_type {};

template <typename... Ts>
struct is_sequence_parser<sequence_parser<Ts...>> : std::true_type {};

template <typename Lhs, typename Rhs>
class sequence_parser : public parser<sequence_parser<Lhs, Rhs>> {
public:
  using lhs_type = Lhs;
  using rhs_type = Rhs;
  using lhs_attribute = typename Lhs::attribute;
  using rhs_attribute = typename Rhs::attribute;

  // LHS = unused && RHS = unused  =>  unused
  // LHS = T && RHS = unused       =>  LHS
  // LHS = unused && RHS = T       =>  RHS
  // LHS = T && RHS = U            =>  std:tuple<T, U>
  using attribute =
    std::conditional_t<
      std::is_same<lhs_attribute, unused_type>{}
        && std::is_same<rhs_attribute, unused_type>{},
      unused_type,
      std::conditional_t<
        std::is_same<lhs_attribute, unused_type>{},
        rhs_attribute,
        std::conditional_t<
          std::is_same<rhs_attribute, unused_type>{},
          lhs_attribute,
          decltype(std::tuple_cat(tuple_wrap<lhs_attribute>{},
                                  tuple_wrap<rhs_attribute>{}))
        >
      >
    >;

  sequence_parser(Lhs lhs, Rhs rhs)
    : lhs_{std::move(lhs)}, rhs_{std::move(rhs)} {
  }

  template <typename Iterator, typename Attribute>
  bool parse(Iterator& f, Iterator const& l, Attribute& a) const {
    auto save = f;
    if (parse_left(f, l, a) && parse_right(f, l, a))
      return true;
    f = save;
    return false;
  }

private:
  template <typename T>
  static constexpr auto depth_helper()
    -> std::enable_if_t<!is_sequence_parser<T>::value, size_t> {
    return 0;
  }

  template <typename T>
  static constexpr auto depth_helper()
    -> std::enable_if_t<
         is_sequence_parser<T>::value
          && (std::is_same<typename T::lhs_attribute, unused_type>::value
              || std::is_same<typename T::rhs_attribute, unused_type>::value),
         size_t
       >
  { return depth_helper<typename T::lhs_type>();
  }

  template <typename T>
  static constexpr auto depth_helper()
    -> std::enable_if_t<
         is_sequence_parser<T>::value
          && ! std::is_same<typename T::lhs_attribute, unused_type>::value
          && ! std::is_same<typename T::rhs_attribute, unused_type>::value,
         size_t
       > {
    return 1 + depth_helper<typename T::lhs_type>();
  }

  static constexpr size_t depth() {
    return depth_helper<sequence_parser>();
  }

  template <typename Iterator>
  bool parse_left(Iterator& f, Iterator const& l, unused_type) const {
    return lhs_.parse(f, l, unused);
  }

  template <typename L, typename T>
  static auto get_helper(T& x)
    -> std::enable_if_t<is_sequence_parser<L>{}, T&> {
    return x;
  }

  template <typename L, typename T>
  static auto get_helper(T& x)
    -> std::enable_if_t<
         ! is_sequence_parser<L>::value,
         decltype(std::get<0>(x))
       > {
    return std::get<0>(x);
  }

  template <typename Iterator, typename T, typename U>
  bool parse_left(Iterator& f, Iterator const& l, std::pair<T, U>& p) const {
    return lhs_.parse(f, l, p.first);
  }

  template <typename Iterator, typename... Ts>
  bool parse_left(Iterator& f, Iterator const& l, std::tuple<Ts...>& t) const {
    return lhs_.parse(f, l, get_helper<lhs_type>(t));
  }

  template <typename Iterator, typename Attribute>
  bool parse_left(Iterator& f, Iterator const& l, Attribute& a) const {
    return lhs_.parse(f, l, a);
  }

  template <typename Iterator>
  bool parse_right(Iterator& f, Iterator const& l, unused_type) const {
    return rhs_.parse(f, l, unused);
  }

  template <typename Iterator, typename T, typename U>
  bool parse_right(Iterator& f, Iterator const& l, std::pair<T, U>& p) const {
    return rhs_.parse(f, l, p.second);
  }

  template <typename Iterator, typename... Ts>
  bool parse_right(Iterator& f, Iterator const& l, std::tuple<Ts...>& t) const {
    return rhs_.parse(f, l, std::get<depth()>(t));
  }

  template <typename Iterator, typename Attribute>
  bool parse_right(Iterator& f, Iterator const& l, Attribute& a) const {
    return rhs_.parse(f, l, a);
  }

  Lhs lhs_;
  Rhs rhs_;
};

} // namespace vast

#endif
