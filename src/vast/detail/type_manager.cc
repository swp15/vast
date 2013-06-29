#include "vast/detail/type_manager.h"

#include <cassert>
#include <exception>
#include "vast/container.h"
#include "vast/logger.h"
#include "vast/serialization.h"
#include "vast/type_info.h"
#include "vast/value.h"

namespace vast {
namespace detail {

bool
type_manager::add(std::type_info const& ti,
                  std::function<global_type_info*(type_id)> f)
{
  if (by_ti_.find(std::type_index(ti)) != by_ti_.end())
    return false;
  if (by_name_.find(ti.name()) != by_name_.end())
    return false;;

  auto gti = f(++id_);

  VAST_LOG_DEBUG("registering new type " << detail::demangle(ti.name()) <<
                 " with id " << id_ << " (mangled name: " << ti.name() << ")");

  by_id_.emplace(gti->id(), gti);
  by_name_.emplace(gti->name(), gti);
  by_ti_.emplace(std::type_index(ti), std::unique_ptr<global_type_info>(gti));

  return true;
}

global_type_info const* type_manager::lookup(std::type_info const& ti) const
{
  auto i = by_ti_.find(std::type_index(ti));
  if (i == by_ti_.end())
    return nullptr;
  return i->second.get();
}

global_type_info const* type_manager::lookup(type_id id) const
{
  auto i = by_id_.find(id);
  if (i == by_id_.end())
    return nullptr;
  return i->second;
}

global_type_info const* type_manager::lookup(std::string const& name) const
{
  auto i = by_name_.find(name);
  if (i == by_name_.end())
    return nullptr;
  return i->second;
}

type_manager* type_manager::create()
{
  return new type_manager;
}

void type_manager::initialize()
{
  announce<bool>();
  announce<int8_t>();
  announce<int16_t>();
  announce<int32_t>();
  announce<int64_t>();
  announce<uint8_t>();
  announce<uint16_t>();
  announce<uint32_t>();
  announce<uint64_t>();
  announce<double>();

  announce<std::string>();
  announce<std::vector<std::string>>();

  announce<address>();
  announce<time_range>();
  announce<time_point>();
  announce<port>();
  announce<prefix>();
  announce<record>();
  announce<regex>();
  announce<set>();
  announce<string>();
  announce<table>();
  announce<vector>();

  announce<value_type>();
  announce<value>();
  announce<std::vector<value>>();
}

void type_manager::destroy()
{
  delete this;
}

void type_manager::dispose()
{
  delete this;
}

} // namespace detail
} // namespace vast
