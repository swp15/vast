#include "vast/bitstream.h"

namespace vast {

null_bitstream::iterator
null_bitstream::iterator::begin(null_bitstream const& n) {
  return iterator{base_iterator::begin(n.bits())};
}

null_bitstream::iterator
null_bitstream::iterator::end(null_bitstream const& n) {
  return iterator{base_iterator::end(n.bits())};
}

null_bitstream::iterator::iterator(base_iterator const& i) : super{i} {
}

auto null_bitstream::iterator::dereference() const
  -> decltype(this->base().position()) {
  return base().position();
}

null_bitstream::sequence_range::sequence_range(null_bitstream const& bs)
  : bits_{&bs.bits_} {
  if (bits_->empty())
    next_block_ = npos;
  else
    next();
}

bool null_bitstream::sequence_range::next_sequence(bitseq& seq) {
  if (next_block_ >= bits_->blocks())
    return false;
  seq.offset = next_block_ * block_width;
  seq.data = bits_->block(next_block_);
  seq.length = block_width;
  seq.type
    = seq.data == 0 || seq.data == all_one ? bitseq::fill : bitseq::literal;
  while (++next_block_ < bits_->blocks())
    if (seq.is_fill() && seq.data == bits_->block(next_block_))
      seq.length += block_width;
    else
      break;
  return true;
}

null_bitstream::null_bitstream(size_type n, bool bit) : bits_{n, bit} {
}

bool null_bitstream::equals(null_bitstream const& other) const {
  return bits_ == other.bits_;
}

void null_bitstream::bitwise_not() {
  if (bits_.empty())
    return;
  bits_.flip();
}

void null_bitstream::bitwise_and(null_bitstream const& other) {
  if (bits_.size() < other.bits_.size())
    bits_.resize(other.bits_.size());
  bits_ &= other.bits_;
}

void null_bitstream::bitwise_or(null_bitstream const& other) {
  if (bits_.size() < other.bits_.size())
    bits_.resize(other.bits_.size());
  bits_ |= other.bits_;
}

void null_bitstream::bitwise_xor(null_bitstream const& other) {
  if (bits_.size() < other.bits_.size())
    bits_.resize(other.bits_.size());
  bits_ ^= other.bits_;
}

void null_bitstream::bitwise_subtract(null_bitstream const& other) {
  if (bits_.size() < other.bits_.size())
    bits_.resize(other.bits_.size());
  bits_ -= other.bits_;
}

void null_bitstream::append_impl(null_bitstream const& other) {
  bits_.append(other.bits());
}

void null_bitstream::append_impl(size_type n, bool bit) {
  bits_.resize(bits_.size() + n, bit);
}

void null_bitstream::append_block_impl(block_type block, size_type bits) {
  bits_.append(block, bits);
}

void null_bitstream::push_back_impl(bool bit) {
  bits_.push_back(bit);
}

void null_bitstream::trim_impl() {
  auto last = find_last();
  if (last == npos)
    bits_.clear();
  else
    bits_.resize(last + 1);
}

void null_bitstream::clear_impl() noexcept {
  bits_.clear();
}

bool null_bitstream::at(size_type i) const {
  return bits_[i];
}

null_bitstream::size_type null_bitstream::size_impl() const {
  return bits_.size();
}

null_bitstream::size_type null_bitstream::count_impl() const {
  return bits_.count();
}

bool null_bitstream::empty_impl() const {
  return bits_.empty();
}

null_bitstream::const_iterator null_bitstream::begin_impl() const {
  return const_iterator::begin(*this);
}

null_bitstream::const_iterator null_bitstream::end_impl() const {
  return const_iterator::end(*this);
}

bool null_bitstream::back_impl() const {
  return bits_[bits_.size() - 1];
}

null_bitstream::size_type null_bitstream::find_first_impl() const {
  return bits_.find_first();
}

null_bitstream::size_type null_bitstream::find_next_impl(size_type i) const {
  return bits_.find_next(i);
}

null_bitstream::size_type null_bitstream::find_last_impl() const {
  return bits_.find_last();
}

null_bitstream::size_type null_bitstream::find_prev_impl(size_type i) const {
  return bits_.find_prev(i);
}

bitvector const& null_bitstream::bits_impl() const {
  return bits_;
}

bool operator==(null_bitstream const& x, null_bitstream const& y) {
  return x.bits_ == y.bits_;
}

bool operator<(null_bitstream const& x, null_bitstream const& y) {
  return x.bits_ < y.bits_;
}

ewah_bitstream::iterator
ewah_bitstream::iterator::begin(ewah_bitstream const& ewah) {
  return {ewah};
}

ewah_bitstream::iterator
ewah_bitstream::iterator::end(ewah_bitstream const& /* ewah */) {
  return {};
}

ewah_bitstream::iterator::iterator(ewah_bitstream const& ewah)
  : ewah_{&ewah}, pos_{0} {
  VAST_ASSERT(ewah_);
  if (ewah_->bits_.blocks() >= 2)
    scan();
  else
    pos_ = npos;
}

bool ewah_bitstream::iterator::equals(iterator const& other) const {
  return pos_ == other.pos_;
}

void ewah_bitstream::iterator::increment() {
  VAST_ASSERT(ewah_);
  VAST_ASSERT(pos_ != npos);
  // Check whether we still have clean 1-blocks to process.
  if (num_clean_ > 0) {
    if (bitvector::bit_index(++pos_) == 0)
      if (--num_clean_ == 0)
        scan();
    return;
  }
  // Then check whether we're processing the last (dirty) block.
  if (idx_ == ewah_->bits_.blocks() - 1) {
    auto i = bitvector::bit_index(pos_);
    auto next = bitvector::next_bit(ewah_->bits_.block(idx_), i);
    pos_ += next == npos ? npos - pos_ : next - i;
    return;
  }
  // Time for the dirty stuff.
  while (num_dirty_ > 0) {
    auto i = bitvector::bit_index(pos_);
    if (i == bitvector::block_width - 1) {
      // We are at last bit in a block and have to move on to the next.
      ++idx_;
      ++pos_;
      if (--num_dirty_ == 0)
        break;
      // There's at least one more dirty block coming afterwards.
      auto next = bitvector::lowest_bit(ewah_->bits_.block(idx_));
      if (next != npos) {
        pos_ += next;
        return;
      }
      // We will never see a dirty block made up entirely of 0s (except for
      // potentially the very last one and here we're only looking at
      // *full* dirty blocks).
      VAST_ASSERT(!"should never happen");
    } else {
      // We're still in the middle of a dirty block.
      auto next = bitvector::next_bit(ewah_->bits_.block(idx_), i);
      if (next != npos) {
        pos_ += next - i;
        return;
      } else {
        // We're done with this block and set the position to end of last block
        // so that we can continue with the code above.
        pos_ += block_width - i - 1;
        continue;
      }
    }
  }
  // Now we have another marker in front of us and have to scan it.
  scan();
}

ewah_bitstream::size_type ewah_bitstream::iterator::dereference() const {
  VAST_ASSERT(ewah_);
  return pos_;
}

void ewah_bitstream::iterator::scan() {
  VAST_ASSERT(pos_ % block_width == 0);
  // We skip over all clean 0-blocks which don't have dirty blocks after them.
  while (idx_ < ewah_->bits_.blocks() - 1 && num_dirty_ == 0) {
    auto marker = ewah_->bits_.block(idx_++);
    num_dirty_ = ewah_bitstream::marker_num_dirty(marker);
    auto num_clean = ewah_bitstream::marker_num_clean(marker);
    if (ewah_bitstream::marker_type(marker)) {
      num_clean_ += num_clean;
      break;
    }
    pos_ += block_width * num_clean;
  }
  // If we have clean 1-blocks, we don't need to do anything because we know
  // that the first 1-bit will be at the current position.
  if (num_clean_ > 0)
    return;
  // Otherwise we need to find the first 1-bit in the next block, which is
  // dirty. However, this dirty block may be the last block and if it doesn't
  // have a single 1-bit we're done.
  auto block = ewah_->bits_.block(idx_);
  if (idx_ == ewah_->bits_.blocks() - 1 && !block) {
    pos_ = npos;
  } else {
    VAST_ASSERT(block);
    pos_ += bitvector::lowest_bit(block);
  }
}

ewah_bitstream::sequence_range::sequence_range(ewah_bitstream const& bs)
  : bits_{&bs.bits_} {
  if (bits_->empty())
    next_block_ = npos;
  else
    next();
}

bool ewah_bitstream::sequence_range::next_sequence(bitseq& seq) {
  if (next_block_ >= bits_->blocks())
    return false;
  auto block = bits_->block(next_block_++);
  if (num_dirty_ > 0 || next_block_ == bits_->blocks()) {
    // The next block must be a dirty block (unless it's the last block, which
    // we don't count in the number of dirty blocks).
    --num_dirty_;
    seq.type = bitseq::literal;
    seq.data = block;
    seq.offset += seq.length;
    seq.length = next_block_ == bits_->blocks() ?
                   bitvector::bit_index(bits_->size() - 1) + 1 :
                   block_width;
  } else {
    // The next block is a marker.
    auto clean = marker_num_clean(block);
    num_dirty_ = marker_num_dirty(block);
    if (clean == 0) {
      // If the marker has no clean blocks, we can't record a fill sequence and
      // have to go to the next (literal) block.
      return next();
    } else {
      seq.type = bitseq::fill;
      seq.data = marker_type(block) ? all_one : 0;
      seq.offset += seq.length;
      seq.length = clean * block_width;

      // If no dirty blocks follow this marker and we have not reached the
      // final dirty block yet, we know that the next block must be a marker as
      // well and check whether we can merge it into the current sequence.
      while (num_dirty_ == 0 && next_block_ + 1 < bits_->blocks()) {
        auto next_marker = bits_->block(next_block_);
        auto next_type = marker_type(next_marker);
        if ((next_type && !seq.data) || (!next_type && seq.data))
          break;
        seq.length += marker_num_clean(next_marker) * block_width;
        num_dirty_ = marker_num_dirty(next_marker);
        ++next_block_;
      }
    }
  }
  return true;
}

ewah_bitstream::ewah_bitstream(size_type n, bool bit) {
  append(n, bit);
}

bool ewah_bitstream::equals(ewah_bitstream const& other) const {
  return bits_ == other.bits_;
}

void ewah_bitstream::bitwise_not() {
  if (bits_.empty())
    return;
  VAST_ASSERT(bits_.blocks() >= 2);
  size_type next_marker = 0;
  size_type i;
  for (i = 0; i < bits_.blocks() - 1; ++i) {
    auto& block = bits_.block(i);
    if (i == next_marker) {
      next_marker += marker_num_dirty(block) + 1;
      if (marker_num_clean(block) > 0)
        block ^= msb_one;
    } else {
      block = ~block;
    }
  }
  // We only flip the active bits in the last block.
  auto idx = bitvector::bit_index(bits_.size() - 1);
  bits_.block(i) ^= all_one >> (block_width - idx - 1);
}

void ewah_bitstream::bitwise_and(ewah_bitstream const& other) {
  *this = and_(*this, other);
}

void ewah_bitstream::bitwise_or(ewah_bitstream const& other) {
  *this = or_(*this, other);
}

void ewah_bitstream::bitwise_xor(ewah_bitstream const& other) {
  *this = xor_(*this, other);
}

void ewah_bitstream::bitwise_subtract(ewah_bitstream const& other) {
  *this = nand_(*this, other);
}

void ewah_bitstream::append_impl(ewah_bitstream const& other) {
  if (other.bits_.empty())
    return;
  if (bits_.empty()) {
    *this = other;
    return;
  }
  bits_.reserve(bits_.size() + other.bits_.size());
  for (auto& seq : sequence_range{other})
    if (seq.is_fill())
      append(seq.length, seq.data);
    else
      append_block(seq.data, seq.length);
}

void ewah_bitstream::append_impl(size_type n, bool bit) {
  if (bits_.empty()) {
    bits_.append(0); // Always begin with an empty marker.
  } else {
    if (num_bits_ % block_width != 0) {
      // Finish the current dirty block.
      auto fill = std::min(n, block_width - (num_bits_ % block_width));
      bits_.resize(bits_.size() + fill, bit);
      num_bits_ += fill;
      n -= fill;
      if (n == 0)
        return;
    }
    // We've filled the last dirty block and are now at a block boundary. At
    // that point we check if we can consolidate the last block.
    integrate_last_block();
  }
  // If whatever is left fits in a literal block, we're done.
  if (n <= block_width) {
    bits_.resize(bits_.size() + n, bit);
    num_bits_ += n;
    return;
  }
  auto clean_blocks = n / block_width;
  auto remaining_bits = n % block_width;
  // Invariant: the last block shall always be dirty.
  if (remaining_bits == 0) {
    VAST_ASSERT(clean_blocks > 0);
    --clean_blocks;
    remaining_bits = block_width;
  }
  VAST_ASSERT(clean_blocks > 0);
  num_bits_ += n;
  auto& marker = bits_.block(last_marker_);
  // If we have currently no dirty blocks and the current marker is of the same
  // type, we reuse it. We also reuse the very first marker if it's still
  // empty.
  if ((last_marker_ == bits_.blocks() - 1 && marker_type(marker) == bit)
      || (last_marker_ == 0 && marker == 0)) {
    auto marker_clean_length = marker_num_clean(marker);
    auto available = marker_clean_max - marker_clean_length;
    auto new_blocks = std::min(available, clean_blocks);
    marker = marker_num_clean(marker, marker_clean_length + new_blocks);
    marker = marker_type(marker, bit);
    clean_blocks -= new_blocks;
  }
  // Now we're ready to stuff the remaining clean words in new markers.
  if (clean_blocks > 0) {
    // If we add new markers and the last block is not dirty, the current
    // marker must not have a dirty count.
    if (last_marker_ == bits_.blocks() - 1)
      marker = marker_num_dirty(marker, 0);
    auto markers = clean_blocks / marker_clean_max;
    auto last = clean_blocks % marker_clean_max;
    while (markers-- > 0)
      bits_.append(marker_type(marker_clean_mask, bit));
    if (last > 0) {
      bits_.append(marker_type(marker_num_clean(0, last), bit));
    }
    last_marker_ = bits_.blocks() - 1;
  }
  bits_.resize(bits_.size() + remaining_bits, bit);
}

void ewah_bitstream::append_block_impl(block_type block, size_type bits) {
  if (bits_.empty())
    bits_.append(0); // Always begin with an empty marker.
  else if (num_bits_ % block_width == 0)
    integrate_last_block();
  if (num_bits_ % block_width == 0) {
    bits_.append(block, bits);
    num_bits_ += bits;
  } else {
    auto used = bits_.extra_bits();
    auto unused = block_width - used;
    if (bits <= unused) {
      bits_.append(block, bits);
      num_bits_ += bits;
    } else {
      bits_.append(block, unused);
      num_bits_ += unused;
      integrate_last_block();
      auto remaining = bits - unused;
      bits_.append(block >> unused, remaining);
      num_bits_ += remaining;
    }
  }
}

void ewah_bitstream::push_back_impl(bool bit) {
  if (bits_.empty())
    bits_.append(0); // Always begin with an empty marker.
  else if (num_bits_ % block_width == 0)
    integrate_last_block();
  bits_.push_back(bit);
  ++num_bits_;
}

void ewah_bitstream::trim_impl() {
  if (empty())
    return;
  auto marker = bits_.block(last_marker_);
  auto num_dirty = marker_num_dirty(marker);
  auto num_clean = marker_num_clean(marker);
  if (bits_.last_block() != 0) {
    auto last_pos = (num_bits_ - 1) % block_width;
    auto high_pos = bitvector::highest_bit(bits_.last_block());
    VAST_ASSERT(last_pos >= high_pos);
    num_bits_ -= last_pos - high_pos;
    return;
  } else if (last_marker_ == 0 && !marker) {
    clear();
    return;
  }
  // Strip the last block of zeros.
  auto last_bits = (num_bits_ - 1) % block_width + 1;
  bits_.resize(bits_.size() - last_bits);
  num_bits_ -= last_bits;
  if (num_dirty != 0) {
    // We have dirty blocks and can simply use the last one, of which we also
    // trim the 0s.
    auto last_pos = (num_bits_ - 1) % block_width;
    auto high_pos = bitvector::highest_bit(bits_.last_block());
    VAST_ASSERT(last_pos >= high_pos);
    num_bits_ -= last_pos - high_pos;
    bits_.block(last_marker_) = marker_num_dirty(marker, --num_dirty);
  } else if (marker_type(marker)) // [*]
  {
    // If there are no more dirty blocks, the last block contains no 1-bit, but
    // the last sequence describes a 1-fill, we can take out a block of 1s and
    // make it the new last block. If this was the last clean block, we have to
    // replace the (now stale) marker with a block of 1s.
    if (num_clean > 1) {
      bits_.block(last_marker_) = marker_num_clean(marker, --num_clean);
      bits_.resize(bits_.size() + block_width);
    }
    bits_.last_block() = all_one;
  } else if (last_marker_ == 0) {
    // We have only one marker with no dirty blocks and at most 0-fills.
    clear();
  } else {
    // The last sequence is a 0-fill with unknown blocks before the last
    // marker. Thus we have to perform a sequential scan from the beginning and
    // stop at the point where no further 1-bits occur.
    size_type total_bits = 0, num_bits = 0, i = 0, prev = 0;
    while (true) {
      auto m = bits_.block(i);
      num_dirty = marker_num_dirty(m);
      num_clean = marker_num_clean(m);
      total_bits += (num_clean + num_dirty) * block_width;
      if (marker_type(m) || num_dirty > 0) {
        prev = i;
        num_bits = total_bits;
      }
      auto off = num_dirty + 1;
      if (i + off + 1 >= bits_.blocks())
        break;
      i += off;
    }
    // If they were the same, it would mean that the last marker was the very
    // first one, which we handle already above.
    VAST_ASSERT(i != last_marker_);
    last_marker_ = prev;
    marker = bits_.block(last_marker_);
    num_dirty = marker_num_dirty(marker);
    num_clean = marker_num_clean(marker);
    // Everything after 'prev' is 0-fill, which we ditch.
    num_bits_ = num_bits;
    bits_.resize((prev + 1 + num_dirty) * block_width);
    if (num_dirty > 0) {
      // We have dirty blocks and just use the last one as our new ultimate
      // dirty block.
      bits_.block(last_marker_) = marker_num_dirty(marker, --num_dirty);
      auto last_pos = (num_bits_ - 1) % block_width;
      auto high_pos = bitvector::highest_bit(bits_.last_block());
      VAST_ASSERT(last_pos >= high_pos);
      num_bits_ -= last_pos - high_pos;
    } else {
      // We have a 1-fill and cut out one for our last dirty block (or replace
      // the block if it was the last).
      if (num_clean > 1) {
        bits_.block(last_marker_) = marker_num_clean(marker, --num_clean);
        bits_.resize(bits_.size() + block_width);
      }
      bits_.last_block() = all_one;
    }
  }
}

void ewah_bitstream::clear_impl() noexcept {
  bits_.clear();
  num_bits_ = last_marker_ = 0;
}

bool ewah_bitstream::at(size_type i) const {
  for (auto& seq : sequence_range{*this})
    if (i >= seq.offset && i < seq.offset + seq.length)
      return seq.is_fill() ? seq.data : seq.data & bitvector::bit_mask(i);
  auto msg = "EWAH element out-of-range element access at index ";
  throw std::out_of_range{msg + std::to_string(i)};
}

ewah_bitstream::size_type ewah_bitstream::size_impl() const {
  return num_bits_;
}

ewah_bitstream::size_type ewah_bitstream::count_impl() const {
  size_type n = 0;
  for (auto& seq : sequence_range{*this})
    if (seq.is_literal())
      n += bitvector::count(seq.data);
    else if (seq.data)
      n += seq.length;
  return n;
}

bool ewah_bitstream::empty_impl() const {
  return num_bits_ == 0;
}

ewah_bitstream::const_iterator ewah_bitstream::begin_impl() const {
  return const_iterator::begin(*this);
}

ewah_bitstream::const_iterator ewah_bitstream::end_impl() const {
  return const_iterator::end(*this);
}

bool ewah_bitstream::back_impl() const {
  return bits_[bits_.size() - 1];
}

ewah_bitstream::size_type ewah_bitstream::find_first_impl() const {
  return find_forward(0);
}

ewah_bitstream::size_type ewah_bitstream::find_next_impl(size_type i) const {
  return i == npos || i + 1 == npos ? npos : find_forward(i + 1);
}

ewah_bitstream::size_type ewah_bitstream::find_last_impl() const {
  return find_backward(npos);
}

ewah_bitstream::size_type ewah_bitstream::find_prev_impl(size_type i) const {
  return i == 0 ? npos : find_backward(i - 1);
}

bitvector const& ewah_bitstream::bits_impl() const {
  return bits_;
}

void ewah_bitstream::integrate_last_block() {
  VAST_ASSERT(num_bits_ % block_width == 0);
  VAST_ASSERT(last_marker_ != bits_.blocks() - 1);
  auto& last_block = bits_.last_block();
  auto blocks_after_marker = bits_.blocks() - last_marker_ - 1;
  // Check whether we can coalesce the current dirty block with the last
  // marker. We can do so if the last block
  //
  //   (i)   is clean
  //   (ii)  directly follows a marker
  //   (iii) is *compatible* with the last marker.
  //
  // Here, compatible means that the last marker type must either match the bit
  // type of the last block or have a run length of 0 (and then change its
  // type).
  if (last_block == 0 || last_block == all_one) {
    // Current dirty block turns out to be clean.
    auto& marker = bits_.block(last_marker_);
    auto clean_length = marker_num_clean(marker);
    auto last_block_type = last_block != 0;
    if (blocks_after_marker == 1 && clean_length == 0) {
      // Adjust the type and counter of the existing marker.
      marker = marker_type(marker, last_block_type);
      marker = marker_num_clean(marker, 1);
      bits_.resize(bits_.size() - block_width);
    } else if (blocks_after_marker == 1
               && last_block_type == marker_type(marker)
               && clean_length != marker_clean_max) {
      // Just update the counter of the existing marker.
      marker = marker_num_clean(marker, clean_length + 1);
      bits_.resize(bits_.size() - block_width);
    } else {
      // Replace the last block with a new marker.
      auto m = marker_num_clean(marker_type(0, last_block_type), 1);
      last_block = m;
      last_marker_ = bits_.blocks() - 1;
    }
  } else {
    // The current block is dirty.
    bump_dirty_count();
  }
}

void ewah_bitstream::bump_dirty_count() {
  VAST_ASSERT(num_bits_ % block_width == 0);
  auto& marker = bits_.block(last_marker_);
  auto num_dirty = marker_num_dirty(marker);
  if (num_dirty == marker_dirty_max) {
    // We need a new marker: replace the current dirty block with a marker and
    // append a new block.
    auto& last_block = bits_.last_block();
    auto dirty_block = last_block;
    last_block = marker_num_dirty(1);
    last_marker_ = bits_.blocks() - 1;
    bits_.append(dirty_block);
  } else {
    // We can still bump the counter of the current marker.
    marker = marker_num_dirty(marker, num_dirty + 1);
  }
}

ewah_bitstream::size_type ewah_bitstream::find_forward(size_type i) const {
  auto range = sequence_range{*this};
  auto seq = range.begin();
  auto end = range.end();
  while (seq != end) {
    // First we skip over all sequences {[a,b) | b <= i} and stop at the
    // first sequence.
    if (seq->offset + seq->length <= i) {
      ++seq;
      continue;
    }
    VAST_ASSERT(seq->offset + seq->length);
    // Then we check the single sequence [a,b) | i >= a && i < b.
    if (seq->data) {
      if (seq->is_fill())
        return i;
      auto idx = bitvector::bit_index(i);
      auto bit =
        // TODO: factor this type of lookup into a utility function.
        idx == 0 ? bitvector::lowest_bit(seq->data) :
                   bitvector::next_bit(seq->data, idx - 1);
      if (bit != npos)
        return seq->offset + bit;
    }
    ++seq;
    break;
  }
  // Finally we investigate the remaining sequences {[a,b) | i > b}.
  while (seq != end) {
    if (seq->data)
      return seq->is_fill() ? seq->offset :
                              seq->offset + bitvector::lowest_bit(seq->data);
    ++seq;
  }
  return npos;
}

ewah_bitstream::size_type ewah_bitstream::find_backward(size_type i) const {
  size_type last = npos;
  auto range = sequence_range{*this};
  for (auto& seq : range) {
    if (seq.offset + seq.length > i) {
      if (!seq.data)
        return last;
      if (seq.is_fill())
        return i;
      auto idx = bitvector::bit_index(i);
      if (idx == bitvector::block_width - 1)
        return seq.offset + bitvector::highest_bit(seq.data);
      auto prev = bitvector::prev_bit(seq.data, idx + 1);
      return prev == npos ? last : seq.offset + prev;
    }
    if (seq.data)
      last = seq.offset + (seq.is_fill() ? seq.length - 1 :
                                           bitvector::highest_bit(seq.data));
  }
  return last;
}

bool operator==(ewah_bitstream const& x, ewah_bitstream const& y) {
  return x.bits_ == y.bits_;
}

bool operator<(ewah_bitstream const& x, ewah_bitstream const& y) {
  return x.bits_ < y.bits_;
}

} // namespace vast
