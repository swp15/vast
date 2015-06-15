#ifndef VAST_ACTOR_SOURCE_BYTE_BASED_H
#define VAST_ACTOR_SOURCE_BYTE_BASED_H

#include <cassert>

#include "vast/actor/source/base.h"
#include "vast/io/getline.h"
#include "vast/io/stream.h"
#include "vast/util/assert.h"

namespace vast {
namespace source {

/// A byte-based source that transforms an input stream into lines.
template <typename Derived>
class byte_based : public base<Derived>
{
protected:
  /// Constructs a a byte-based source.
  /// @param name The name of the actor.
  /// @param is The input stream to read from.
  byte_based(char const* name, std::unique_ptr<io::input_stream> is)
    : base<Derived>{name},
      input_stream_{std::move(is)}
  {
    VAST_ASSERT(input_stream_ != nullptr);
  }

  /// Imports the byte-file.
  /// @returns an byte-vector on success.
  std::vector<uint8_t> import()
  {
  	while (input_stream_->next(reinterpret_cast<const void**>(&buf), &size))
  	{
    		for (size_t i = 0; i < size; ++i)
    		{
			bvector.push_back(buf[i]);
		}
	}	
	return bvector;
  }

private:
  std::unique_ptr<io::input_stream> input_stream_;
  std::vector<uint8_t> bvector;
  uint8_t const* buf;
  size_t size;
};

} // namespace source
} // namespace vast

#endif
