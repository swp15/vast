#ifndef VAST_ACTOR_SOURCE_BGPDUMPBINARY_H
#define VAST_ACTOR_SOURCE_BGPDUMPBINARY_H

#include "vast/schema.h"
#include "vast/actor/source/byte_based.h"

namespace vast {
namespace source {

/// A source reading ASCII output from the BGPDump utility.
class bgpdumpbinary : public byte_based<bgpdumpbinary>
{
public:
  /// Spawns a BGPDump source.
  /// @param is The input stream to read BGPDump data logs from.
  bgpdumpbinary(std::unique_ptr<io::input_stream> is);

  schema sniff();

  void set(schema const& sch);

  result<event> extract();

private:
  std::vector<uint8_t> bvector;
  std::vector<uint8_t>::iterator counter;
  uint8_t funcCounter = 0;

  /*std::string separator_ = "|";
  type state_change_type_;*/
};

} // namespace source
} // namespace vast

#endif
