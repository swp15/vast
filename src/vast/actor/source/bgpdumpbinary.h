#ifndef VAST_ACTOR_SOURCE_BGPDUMPBINARY_H
#define VAST_ACTOR_SOURCE_BGPDUMPBINARY_H

#include "vast/schema.h"
#include "vast/actor/source/byte_based.h"

namespace vast {
namespace source {

/// A source reading binary files.
class bgpdumpbinary : public byte_based<bgpdumpbinary>
{
public:
  /// Spawns a BGPDumpbinar< source.
  /// @param is The input stream to read binary data logs from.
  bgpdumpbinary(std::unique_ptr<io::input_stream> is);

  schema sniff();

  void set(schema const& sch);

  result<event> extract();

private:
  std::stringstream packet_stream;
  std::string packet_string;
  std::vector<uint8_t> bvector;
  std::vector<uint8_t>::iterator counter;
  std::vector<event> event_queue;
  bool imported = false;
  int prefixCounter = 0;

  type announce_type_;
  type route_type_;
  type withdraw_type_;
  type state_change_type_;
};

} // namespace source
} // namespace vast

#endif
