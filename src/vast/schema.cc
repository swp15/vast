#include "vast/schema.h"

#include "vast/exception.h"
#include "vast/logger.h"
#include "vast/to_string.h"
#include "vast/detail/ast/schema.h"
#include "vast/detail/parser/schema.h"
#include "vast/fs/fstream.h"

namespace vast {
namespace detail {

class type_maker
{
public:
  typedef intrusive_ptr<schema::type> result_type;

  type_maker(schema const& s)
    : schema_(s)
  {
  }

  result_type operator()(ast::schema::basic_type type) const
  {
    switch (type)
    {
      default:
        throw exception("missing type implementation");
      case ast::schema::bool_type:
        return new schema::bool_type;
      case ast::schema::int_type:
        return new schema::int_type;
      case ast::schema::uint_type:
        return new schema::uint_type;
      case ast::schema::double_type:
        return new schema::double_type;
      case ast::schema::duration_type:
        return new schema::time_frame_type;
      case ast::schema::timepoint_type:
        return new schema::time_point_type;
      case ast::schema::string_type:
        return new schema::string_type;
      case ast::schema::regex_type:
        return new schema::regex_type;
      case ast::schema::address_type:
        return new schema::address_type;
      case ast::schema::prefix_type:
        return new schema::prefix_type;
      case ast::schema::port_type:
        return new schema::port_type;
    }
  }

  result_type operator()(ast::schema::enum_type const& type) const
  {
    auto t = new schema::enum_type;
    t->fields = type.fields;
    return t;
  }

  result_type operator()(ast::schema::vector_type const& type) const
  {
    auto t = new schema::vector_type;
    t->elem_type = create_type_info(type.element_type);
    return t;
  }

  result_type operator()(ast::schema::set_type const& type) const
  {
    auto t = new schema::set_type;
    t->elem_type = create_type_info(type.element_type);
    return t;
  }

  result_type operator()(ast::schema::table_type const& type) const
  {
    auto t = new schema::table_type;
    t->key_type = create_type_info(type.key_type);
    t->value_type = create_type_info(type.value_type);
    return t;
  }

  result_type operator()(ast::schema::record_type const& type) const
  {
    // TODO: Parse argument attributes.
    auto record = new schema::record_type;
    for (auto& arg : type.args)
      record->args.push_back({arg.name, create_type_info(arg.type)});
    return record;
  }

  schema::type_info create_type_info(ast::schema::type_info const& ti) const
  {
    auto info = schema_.info(ti.name);
    return info ? info :
      schema::type_info{ti.name, {}, boost::apply_visitor(*this, ti.type)};
  }

private:
  schema const& schema_;
};

class schema_maker
{
public:
  typedef void result_type;

  schema_maker(schema& s)
    : maker_(s)
    , schema_(s)
  {
  }

  result_type operator()(ast::schema::type_declaration const& td) const
  {
    if (auto p = boost::get<ast::schema::type_type>(&td.type))
      schema_.add_type(td.name, boost::apply_visitor(std::ref(maker_), *p));
    else if (auto p = boost::get<ast::schema::type_info>(&td.type))
      if (! schema_.add_type_alias(p->name, td.name))
        throw error::schema("could not create type alias");
  }

  result_type operator()(ast::schema::event_declaration const& ed) const
  {
    schema::event e;
    e.name = ed.name;

    // TODO: Parse argument attributes.
    if (ed.args)
      for (auto& arg : *ed.args)
        e.args.push_back({arg.name, maker_.create_type_info(arg.type)});

    schema_.add_event(std::move(e));
  }

private:
  type_maker maker_;
  schema& schema_;
};

} // namespace detail

void schema::load(std::string const& contents)
{
  types_.clear();
  events_.clear();

  DBG(meta) << "parsing schema";

  auto i = contents.begin();
  auto end = contents.end();
  typedef std::string::const_iterator iterator_type;
  detail::parser::error_handler<iterator_type> on_error(i, end);
  detail::parser::schema<iterator_type> grammar(on_error);
  detail::parser::skipper<iterator_type> skipper;
  detail::ast::schema::schema ast;
  bool success = phrase_parse(i, end, grammar, skipper, ast);
  if (! success || i != end)
    throw error::schema("syntax error");

  detail::type_maker type_maker(*this);
  grammar.basic_type_.for_each(
      [&](std::string const& name, detail::ast::schema::type_info const& info)
      {
        auto t = boost::apply_visitor(std::ref(type_maker), info.type);
        add_type(name, t);
      });

  detail::schema_maker schema_maker(*this);
  for (auto& statement : ast)
    boost::apply_visitor(std::ref(schema_maker), statement);

  DBG(meta) << "parsed schema successfully";
}

void schema::read(const std::string& filename)
{
  fs::ifstream in(filename);

  std::string storage;
  in.unsetf(std::ios::skipws);
  std::copy(std::istream_iterator<char>(in),
            std::istream_iterator<char>(),
            std::back_inserter(storage));

  load(storage);
}

void schema::write(std::string const& filename) const
{
  fs::ofstream(filename) << to_string(*this);
}

schema::type_info schema::info(std::string const& name) const
{
  auto i = std::find_if(
      types_.begin(),
      types_.end(),
      [&name](type_info const& ti) { return ti.name == name; });

  return i != types_.end() ? *i : type_info();
}

void schema::add_type(std::string name, intrusive_ptr<type> t)
{
  if (info(name))
    throw error::schema("duplicate type");

  DBG(meta) << "adding type " << name << ": " << to_string(*t);
  types_.push_back({std::move(name), {}, t});
}

bool schema::add_type_alias(std::string const& type, std::string const& alias)
{
  auto i = std::find_if(
      types_.begin(),
      types_.end(),
      [&type](type_info const& ti) { return ti.name == type; });

  if (i == types_.end())
    return false;

  add_type(alias, i->type);

  DBG(meta) << "making type alias: " << alias << " -> " << type;
  i->aliases.push_back(alias);
  return true;
}

void schema::add_event(event e)
{
  DBG(meta) << "adding event: " << to_string(e);
  events_.emplace_back(std::move(e));
}

} // namespace vast