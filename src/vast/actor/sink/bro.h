#ifndef VAST_ACTOR_SINK_BRO_H
#define VAST_ACTOR_SINK_BRO_H

#include <memory>
#include <unordered_map>

#include "vast/filesystem.h"
#include "vast/io/file_stream.h"
#include "vast/actor/sink/base.h"

namespace vast {
namespace sink {

/// A sink generating Bro logs.
class bro : public base<bro> {
public:
  static constexpr char sep = '\x09';
  static constexpr auto set_separator = ",";
  static constexpr auto empty_field = "(empty)";
  static constexpr auto unset_field = "-";
  static constexpr auto format = "%Y-%m-%d-%H-%M-%S";

  static std::string make_header(type const& t);
  static std::string make_footer();

  /// Spawns a Bro sink.
  /// @param p The output path.
  bro(path p);

  bool process(event const& e);

private:
  using map_type
    = std::unordered_map<std::string, std::unique_ptr<io::file_output_stream>>;

  path dir_;
  map_type streams_;
};

} // namespace sink
} // namespace vast

#endif
