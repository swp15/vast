#ifndef VAST_EVENT_INDEX_H
#define VAST_EVENT_INDEX_H

#include <cppa/cppa.hpp>
#include "vast/event.h"
#include "vast/expression.h"
#include "vast/file_system.h"
#include "vast/logger.h"
#include "vast/offset.h"
#include "vast/bitmap_index/string.h"
#include "vast/bitmap_index/time.h"
#include "vast/io/serialization.h"

namespace vast {

/// Indexes a certain aspect of events.
template <typename Derived>
class event_index : public cppa::event_based_actor
{
public:
  /// Spawns an event index.
  /// @param dir The absolute path on the file system.
  event_index(path dir)
    : dir_{std::move(dir)}
  {
  }

  /// Implements `event_based_actor::init`.
  virtual void init() final
  {
    using namespace cppa;

    VAST_LOG_ACT_VERBOSE(derived().name(), "spawned");

    if (exists(dir_))
      derived().load();
    else
      mkdir(dir_);

    become(
        on(atom("kill")) >> [=]
        {
          quit();
        },
        on(atom("flush")) >> [=]
        {
          derived().store();
        },
        on_arg_match >> [=](event const& e)
        {
          if (! derived().index(e))
          {
            VAST_LOG_ACT_ERROR(derived().name(), "failed to index event " << e);
            quit();
          }
        },
        on_arg_match >> [=](expression const& e)
        {
          if (option<bitstream> result = derived().lookup(e))
            reply(std::move(*result));
          else
            reply(atom("miss"));
        });
  }

  /// Overrides `event_based_actor::on_exit`.
  virtual void on_exit() final
  {
    derived().store();
    VAST_LOG_ACT_VERBOSE(derived().name(), "terminated");
  }

protected:
  path const dir_;

private:
  Derived const& derived() const
  {
    return static_cast<Derived const&>(*this);
  }

  Derived& derived()
  {
    return static_cast<Derived&>(*this);
  }
};

class event_meta_index : public event_index<event_meta_index>
{
public:
  event_meta_index(path dir);

  char const* name() const;
  void load();
  void store();
  bool index(event const& e);
  option<bitstream> lookup(expression const& e);

private:
  bool index_impl(record const& r, uint64_t id, offset& o);

  time_bitmap_index timestamp_;
  string_bitmap_index name_;
};

class event_arg_index : public event_index<event_arg_index>
{
public:
  event_arg_index(path dir);

  char const* name() const;
  void load();
  void store();
  bool index(event const& e);
  option<bitstream> lookup(expression const& e);

private:
  bool index_impl(record const& r, uint64_t id, offset& o);

  std::map<offset, std::shared_ptr<bitmap_index>> args_;
  std::map<value_type, std::vector<std::shared_ptr<bitmap_index>>> types_;
};

} // namespace vast

#endif