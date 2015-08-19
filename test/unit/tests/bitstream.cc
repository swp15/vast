#include "vast/bitstream.h"
#include "vast/bitstream_polymorphic.h"
#include "vast/concept/printable/to_string.h"
#include "vast/concept/printable/vast/bitstream.h"
#include "vast/concept/serializable/io.h"
#include "vast/concept/serializable/vast/bitstream_polymorphic.h"

#define SUITE bitstream
#include "test.h"

using namespace vast;

namespace {

ewah_bitstream make_ewah1() {
  ewah_bitstream ewah;
  ewah.append(10, true);
  ewah.append(20, false);
  ewah.append(40, true);
  ewah.push_back(false);
  ewah.push_back(true);
  ewah.push_back(false);
  ewah.append(53, true);
  ewah.push_back(false);
  ewah.push_back(false);
  ewah.append(192, true);
  ewah.append(64 * 16, false);
  ewah.append(64ull * ((1ull << 32) - 1), true);
  ewah.push_back(false);
  ewah.append(63, true);
  for (auto i = 0; i < 64; ++i)
    ewah.push_back(i % 2 == 0);
  ewah.append((1ull << (32 + 3)) * 64, false);
  ewah.push_back(true);
  return ewah;
}

ewah_bitstream make_ewah2() {
  ewah_bitstream ewah;
  ewah.push_back(false);
  ewah.push_back(true);
  ewah.append(421, false);
  ewah.append(2, true);
  return ewah;
}

ewah_bitstream make_ewah3() {
  ewah_bitstream ewah;
  ewah.append(222, true);
  ewah.push_back(false);
  ewah.push_back(true);
  ewah.push_back(false);
  ewah.append_block(0xcccccccccc);
  ewah.push_back(false);
  ewah.push_back(true);
  return ewah;
}

} // namespace <anonymous>

TEST(EWAH algorithm 1) {
  ewah_bitstream ewah;
  ewah.append(10, true);
  ewah.append(20, false);

  // Cause the first dirty block to overflow and bumps the dirty counter of
  // the first marker to 1.
  ewah.append(40, true);

  // Fill up another dirty block.
  ewah.push_back(false);
  ewah.push_back(true);
  ewah.push_back(false);
  ewah.append(53, true);
  ewah.push_back(false);
  ewah.push_back(false);

  CHECK(ewah.size() == 128);

  // Bump the dirty count to 2 and fill up the current dirty block.
  ewah.push_back(true);
  ewah.append(63, true);

  auto str =
    "0000000000000000000000000000000000000000000000000000000000000010\n"
    "1111111111111111111111111111111111000000000000000000001111111111\n"
    "0011111111111111111111111111111111111111111111111111111010111111\n"
    "1111111111111111111111111111111111111111111111111111111111111111";

  REQUIRE(to_string(ewah) == str);

  // Appending anything now transforms the last block into a marker, because
  // it it turns out it was all 1s.
  ewah.push_back(true);

  str =
    "0000000000000000000000000000000000000000000000000000000000000010\n"
    "1111111111111111111111111111111111000000000000000000001111111111\n"
    "0011111111111111111111111111111111111111111111111111111010111111\n"
    "1000000000000000000000000000000010000000000000000000000000000000\n"
    "                                                               1";

  REQUIRE(to_string(ewah) == str);
  CHECK(ewah.size() == 193);

  // Fill up the dirty block and append another full block. This bumps the
  // clean count of the last marker to 2.
  ewah.append(63, true);
  ewah.append(64, true);

  // Now we'll add some 0 bits. We had a complete block left, so that make the
  // clean count of the last marker 3.
  ewah.append(64, false);

  CHECK(ewah.size() == 384);

  // Add 15 clean blocks of 0, of which 14 get merged with the previous
  // marker and 1 remains a non-marker block. That yields a marker count of
  // 1111 (15).
  ewah.append(64 * 15, false);

  str =
    "0000000000000000000000000000000000000000000000000000000000000010\n"
    "1111111111111111111111111111111111000000000000000000001111111111\n"
    "0011111111111111111111111111111111111111111111111111111010111111\n"
    "1000000000000000000000000000000110000000000000000000000000000000\n"
    "0000000000000000000000000000011110000000000000000000000000000000\n"
    "0000000000000000000000000000000000000000000000000000000000000000";

  REQUIRE(to_string(ewah) == str);
  CHECK(ewah.size() == 384 + 64 * 15);

  // Now we're add the maximum number of new blocks with value 1. This
  // amounts to 64 * (2^32-1) = 274,877,906,880 bits in 2^32-2 blocks. Note
  // that the maximum value of a clean block is 2^32-1, but the invariant
  // requires the last block to be dirty, so we have to subtract yet another
  // block.
  ewah.append(64ull * ((1ull << 32) - 1), true);

  // Appending a single bit here just triggers the coalescing of the last
  // block with the current marker, making the clean count have the maximum
  // value of 2^32-1.
  ewah.push_back(false);

  str =
    "0000000000000000000000000000000000000000000000000000000000000010\n"
    "1111111111111111111111111111111111000000000000000000001111111111\n"
    "0011111111111111111111111111111111111111111111111111111010111111\n"
    "1000000000000000000000000000000110000000000000000000000000000000\n"
    "0000000000000000000000000000100000000000000000000000000000000000\n"
    "1111111111111111111111111111111110000000000000000000000000000000\n"
    "                                                               0";

  REQUIRE(to_string(ewah) == str);
  CHECK(ewah.size() == 1344 + 274877906880ull + 1);

  /// Complete the block as dirty.
  ewah.append(63, true);

  /// Create another full dirty block, just so that we can check that the
  /// dirty counter works properly.
  for (auto i = 0; i < 64; ++i)
    ewah.push_back(i % 2 == 0);

  CHECK(ewah.size() == 274877908352ull);

  // Now we add 2^3 full markers. Because the maximum clean count is 2^32-1,
  // we end up with 8 full markers and 7 clean blocks.
  ewah.append((1ull << (32 + 3)) * 64, false);

  str =
    "0000000000000000000000000000000000000000000000000000000000000010\n"
    "1111111111111111111111111111111111000000000000000000001111111111\n"
    "0011111111111111111111111111111111111111111111111111111010111111\n"
    "1000000000000000000000000000000110000000000000000000000000000000\n"
    "0000000000000000000000000000100000000000000000000000000000000000\n"
    "1111111111111111111111111111111110000000000000000000000000000010\n"
    "1111111111111111111111111111111111111111111111111111111111111110\n"
    "0101010101010101010101010101010101010101010101010101010101010101\n"
    "0111111111111111111111111111111110000000000000000000000000000000\n"
    "0111111111111111111111111111111110000000000000000000000000000000\n"
    "0111111111111111111111111111111110000000000000000000000000000000\n"
    "0111111111111111111111111111111110000000000000000000000000000000\n"
    "0111111111111111111111111111111110000000000000000000000000000000\n"
    "0111111111111111111111111111111110000000000000000000000000000000\n"
    "0111111111111111111111111111111110000000000000000000000000000000\n"
    "0111111111111111111111111111111110000000000000000000000000000000\n"
    "0000000000000000000000000000001110000000000000000000000000000000\n"
    "0000000000000000000000000000000000000000000000000000000000000000";

  REQUIRE(to_string(ewah) == str);
  CHECK(ewah.size() == 274877908352ull + 2199023255552ull);

  /// Adding another bit just consolidates the last clean block with the
  /// last marker.
  ewah.push_back(true);

  str =
    "0000000000000000000000000000000000000000000000000000000000000010\n"
    "1111111111111111111111111111111111000000000000000000001111111111\n"
    "0011111111111111111111111111111111111111111111111111111010111111\n"
    "1000000000000000000000000000000110000000000000000000000000000000\n"
    "0000000000000000000000000000100000000000000000000000000000000000\n"
    "1111111111111111111111111111111110000000000000000000000000000010\n"
    "1111111111111111111111111111111111111111111111111111111111111110\n"
    "0101010101010101010101010101010101010101010101010101010101010101\n"
    "0111111111111111111111111111111110000000000000000000000000000000\n"
    "0111111111111111111111111111111110000000000000000000000000000000\n"
    "0111111111111111111111111111111110000000000000000000000000000000\n"
    "0111111111111111111111111111111110000000000000000000000000000000\n"
    "0111111111111111111111111111111110000000000000000000000000000000\n"
    "0111111111111111111111111111111110000000000000000000000000000000\n"
    "0111111111111111111111111111111110000000000000000000000000000000\n"
    "0111111111111111111111111111111110000000000000000000000000000000\n"
    "0000000000000000000000000000010000000000000000000000000000000000\n"
    "                                                               1";

  REQUIRE(to_string(ewah) == str);
  CHECK(ewah.size() == 2473901163905);

  REQUIRE(ewah == make_ewah1());
}

TEST(EWAH algorithm 2) {
  ewah_bitstream ewah;
  ewah.push_back(false);
  ewah.push_back(true);
  ewah.append(421, false);
  ewah.push_back(true);
  ewah.push_back(true);

  auto str =
    "0000000000000000000000000000000000000000000000000000000000000001\n"
    "0000000000000000000000000000000000000000000000000000000000000010\n"
    "0000000000000000000000000000001010000000000000000000000000000000\n"
    "                       11000000000000000000000000000000000000000";

  REQUIRE(to_string(ewah) == str);
  REQUIRE(ewah == make_ewah2());
}

TEST(EWAH algorithm 3) {
  ewah_bitstream ewah;
  ewah.append(222, true);
  ewah.push_back(false);
  ewah.push_back(true);
  ewah.push_back(false);
  ewah.append_block(0xcccccccccc);
  ewah.push_back(false);
  ewah.push_back(true);

  auto str =
    "1000000000000000000000000000000110000000000000000000000000000001\n"
    "1001100110011001100110011001100010111111111111111111111111111111\n"
    "                             10000000000000000000000000110011001";

  REQUIRE(to_string(ewah) == str);
  REQUIRE(ewah == make_ewah3());
}

TEST(polymorphic) {
  bitstream empty;
  CHECK(!empty);

  bitstream x{null_bitstream{}}, y;
  REQUIRE(x);
  CHECK(x.append(3, true));
  CHECK(x.size() == 3);

  std::vector<uint8_t> buf;
  save(buf, x);
  load(buf, y);
  CHECK(y.size() == 3);
}

TEST(bitwise operations NULL) {
  null_bitstream x;
  REQUIRE(x.append(3, true));
  REQUIRE(x.append(7, false));
  REQUIRE(x.push_back(true));
  CHECK(to_string(x) == "11100000001");
  CHECK(to_string(~x) == "00011111110");

  null_bitstream y;
  REQUIRE(y.append(2, true));
  REQUIRE(y.append(4, false));
  REQUIRE(y.append(3, true));
  REQUIRE(y.push_back(false));
  REQUIRE(y.push_back(true));
  CHECK(to_string(y) == "11000011101");
  CHECK(to_string(~y) == "00111100010");

  CHECK(to_string(x & y) == "11000000001");
  CHECK(to_string(x | y) == "11100011101");
  CHECK(to_string(x ^ y) == "00100011100");
  CHECK(to_string(x - y) == "00100000000");
  CHECK(to_string(y - x) == "00000011100");

  std::vector<null_bitstream> v;
  v.push_back(x);
  v.push_back(y);
  v.emplace_back(x - y);

  // The original vector contains the following (from LSB to MSB):
  // 11100000001
  // 11000011101
  // 00100000000
  std::string str;
  auto i = std::back_inserter(str);
  REQUIRE(print(i, v));
  CHECK(
      str ==
      "110\n"
      "110\n"
      "101\n"
      "000\n"
      "000\n"
      "000\n"
      "010\n"
      "010\n"
      "010\n"
      "000\n"
      "110\n"
      );

  null_bitstream z;
  z.push_back(false);
  z.push_back(true);
  z.append(1337, false);
  z.trim();
  CHECK(z.size() == 2);
  CHECK(to_string(z) == "01");
}

TEST(trimming EWAH) {
  auto ewah1 = make_ewah1();
  auto ewah2 = make_ewah2();
  auto ewah3 = make_ewah3();

  // NOPs---these all end in a 1.
  auto ewah_trimmed = ewah1;
  ewah_trimmed.trim();
  CHECK(ewah1 == ewah_trimmed);
  auto ewah2_trimmed = ewah2;
  ewah2_trimmed.trim();
  CHECK(ewah2 == ewah2_trimmed);
  auto ewah3_trimmed = ewah3;
  ewah3_trimmed.trim();
  CHECK(ewah3 == ewah3_trimmed);

  ewah_bitstream ebs;
  ebs.append(20, false);
  ebs.trim();
  CHECK(ebs.size() == 0);
  CHECK(to_string(ebs) == "");

  ebs.push_back(true);
  ebs.append(30, false);
  ebs.trim();
  CHECK(ebs.size() == 1);
  ebs.clear();

  ebs.append(64, true);
  ebs.trim();
  CHECK(ebs.size() == 64);
  ebs.clear();

  ebs.push_back(false);
  ebs.push_back(true);
  ebs.append(100, false);
  ebs.trim();
  CHECK(ebs.size() == 2);
  ebs.clear();

  ebs.append(192, true);
  ebs.append(10, false);
  ebs.trim();
  CHECK(ebs.size() == 192);
  ebs.clear();

  ebs.append(192, true);
  ebs.append(128, false);
  ebs.trim();
  CHECK(ebs.size() == 192);
  ebs.clear();

  ebs.append(192, true);
  ebs.append(128, false);
  ebs.append(192, true);
  ebs.append(128, false); // Gets eaten.
  ebs.trim();
  CHECK(ebs.size() == 192 + 128 + 192);
  ebs.clear();

  ebs.append(192, true);
  ebs.append(128, false);
  ebs.append(192, true);
  ebs.append_block(0xf00f00);
  ebs.append_block(0xf00f00);
  ebs.append_block(0xf00f00); // Trimmed to length 24.
  ebs.append(128, false);
  ebs.trim();
  CHECK(ebs.size() == 192 + 128 + 192 + 64 + 64 + 24);
  ebs.clear();
}

TEST(bitwise iteration EWAH) {
  auto ewah1 = make_ewah1();
  auto ewah2 = make_ewah2();

  auto i = ewah1.begin();
  for (size_t j = 0; j < 10; ++j)
    CHECK(*i++ == j);

  for (size_t j = 30; j < 70; ++j)
    CHECK(*i++ == j);

  CHECK(*i++ == 71);
  for (size_t j = 73; j < 73 + 53; ++j)
    CHECK(*i++ == j);

  // The block at index 4 has 3 clean 1-blocks.
  for (size_t j = 128; j < 128 + 3 * 64; ++j)
    CHECK(*i++ == j);

  // The block at index 5 has 2^4 clean 0-blocks, which iteration should skip.
  ewah_bitstream::size_type next = 320 + 64 * (1 << 4);
  CHECK(*i == next);

  // Now we're facing 2^32 clean 1-blocks. That's too much to iterate over.
  // Let's try something simpler.

  i = ewah2.begin();
  CHECK(*i == 1);
  CHECK(*++i == 423);
  CHECK(*++i == 424);
  CHECK(++i == ewah2.end());

  // While we're at it, let's test operator[] access as well.
  CHECK(! ewah2[0]);
  CHECK(ewah2[1]);
  CHECK(! ewah2[2]);
  CHECK(! ewah2[63]);
  CHECK(! ewah2[64]);
  CHECK(! ewah2[65]);
  CHECK(! ewah2[384]);
  CHECK(! ewah2[385]);
  CHECK(! ewah2[422]);
  CHECK(ewah2[423]);
  CHECK(ewah2[424]);

  ewah_bitstream ebs;
  ebs.append(1000, false);
  for (auto i = 0; i < 256; ++i)
    ebs.push_back(i % 4 == 0);
  ebs.append(1000, false);

  ewah_bitstream::size_type cnt = 1000;
  i = ebs.begin();
  while (i != ebs.end()) {
    CHECK(*i == cnt);
    cnt += 4;
    ++i;
  }
}

TEST(iterator increment bugfix EWAH) {
  ewah_bitstream ebs;
  ebs.push_back(false);
  ebs.append(1023, true);
  auto begin = ebs.begin();
  auto end = ebs.end();
  size_t n = 1;
  while (begin != end)
    REQUIRE(*begin++ == n++);
  CHECK(n == 1024);
}

TEST(element access EWAH) {
  auto ewah1 = make_ewah1();
  CHECK(ewah1[0]);
  CHECK(ewah1[9]);
  CHECK(!ewah1[10]);
  CHECK(ewah1[64]);
  CHECK(!ewah1[1024]);
  CHECK(ewah1[1344]);
  CHECK(ewah1[2473901163905 - 1]);
}

TEST(finding EWAH) {
  auto ewah1 = make_ewah1();
  CHECK(ewah1.find_first() == 0);
  CHECK(ewah1.find_next(0) == 1);
  CHECK(ewah1.find_next(8) == 9);
  CHECK(ewah1.find_next(9) == 30);
  CHECK(ewah1.find_next(10) == 30);
  CHECK(ewah1.find_next(63) == 64);
  CHECK(ewah1.find_next(64) == 65);
  CHECK(ewah1.find_next(69) == 71);
  CHECK(ewah1.find_next(319) == 1344);
  CHECK(ewah1.find_next(320) == 1344);
  CHECK(ewah1.find_next(2473901163903) == 2473901163904);
  CHECK(ewah1.find_next(2473901163904) == ewah_bitstream::npos);
  CHECK(ewah1.find_last() == 2473901163905 - 1);
  CHECK(ewah1.find_prev(128) == 125);
  CHECK(ewah1.find_prev(320) == 319);
  CHECK(ewah1.find_prev(2473901163904) == 274877908288 + 62);

  auto ewah2 = make_ewah2();
  CHECK(ewah2.find_first() == 1);
  CHECK(ewah2.find_next(1) == 423);
  CHECK(ewah2.find_last() == 424);
  CHECK(ewah2.find_prev(1) == ewah_bitstream::npos);
  CHECK(ewah2.find_prev(423) == 1);
  CHECK(ewah2.find_prev(424) == 423);

  auto ewah3 = make_ewah3();
  CHECK(ewah3.find_first() == 0);
  CHECK(ewah3.find_next(3 * 64 + 29) == 3 * 64 + 29 + 2 /* = 223 */);
  CHECK(ewah3.find_next(223) == 223 + 4); // Skip 3 zeros.
  CHECK(ewah3.find_last() == ewah3.size() - 1);
  CHECK(ewah3.find_prev(ewah3.size() - 1) == ewah3.size() - 1 - 26);

  ewah_bitstream ebs;
  ebs.append(44, false);
  ebs.append(3, true);
  ebs.append(17, false);
  ebs.append(31, false);
  ebs.append(4, true);

  CHECK(ebs.find_first() == 44);
  CHECK(ebs.find_next(44) == 45);
  CHECK(ebs.find_next(45) == 46);
  CHECK(ebs.find_next(46) == 44 + 3 + 17 + 31);
  CHECK(ebs.find_next(49) == 44 + 3 + 17 + 31);
  CHECK(ebs.find_last() == ebs.size() - 1);

  ebs.clear();
  ebs.append(64, true);
  ebs.append(32, false);
  ebs.append(20, true);

  CHECK(ebs.find_prev(0) == ewah_bitstream::npos);
  CHECK(ebs.find_prev(63) == 62);
  CHECK(ebs.find_next(63) == 96);
  bitstream::size_type i;
  for (i = 64; i < 64 + 32; ++i) {
    CHECK(ebs.find_prev(i) == 63);
    CHECK(ebs.find_next(i) == 96);
  }
  while (i < 64 + 32 + 20 - 1) {
    CHECK(ebs.find_next(i) == i + 1);
    ++i;
    CHECK(ebs.find_prev(i) == i - 1);
  }

  // Now we're at the last bit.
  CHECK(i == 64 + 32 + 20 - 1);
  CHECK(ebs.find_prev(i) == 64 + 32 + 20 - 2);
  CHECK(ebs.find_next(i) == ewah_bitstream::npos);

  ebs.clear();
  ebs.append(64, true);
  ebs.append(32, true);
  ebs.append(20, false);

  CHECK(ebs.find_next(63) == 64);
  i = 64;
  while (i < 64 + 32 - 1) {
    CHECK(ebs.find_next(i) == i + 1);
    ++i;
    CHECK(ebs.find_prev(i) == i - 1);
  }
  while (i < 64 + 32 + 20 - 1) {
    CHECK(ebs.find_next(i) == ewah_bitstream::npos);
    ++i;
    CHECK(ebs.find_prev(i) == 64 + 32 - 1);
  }
  CHECK(ebs.find_next(64 + 31) == ewah_bitstream::npos);
}

TEST(bitwise NOT EWAH) {
  ewah_bitstream ebs;
  ebs.push_back(true);
  ebs.push_back(false);
  ebs.append(30, true);
  ebs.push_back(false);

  ewah_bitstream comp;
  comp.push_back(false);
  comp.push_back(true);
  comp.append(30, false);
  comp.push_back(true);

  auto str =
    "0000000000000000000000000000000000000000000000000000000000000000\n"
    "                               100000000000000000000000000000010";

  CHECK(~ebs == comp);
  CHECK(ebs == ~comp);
  CHECK(~~ebs == ebs);
  CHECK(to_string(~ebs) == str);

  str =
    "0000000000000000000000000000000000000000000000000000000000000010\n"
    "0000000000000000000000000000000000111111111111111111110000000000\n"
    "1100000000000000000000000000000000000000000000000000000101000000\n"
    "0000000000000000000000000000000110000000000000000000000000000000\n"
    "1000000000000000000000000000100000000000000000000000000000000000\n"
    "0111111111111111111111111111111110000000000000000000000000000010\n"
    "0000000000000000000000000000000000000000000000000000000000000001\n"
    "1010101010101010101010101010101010101010101010101010101010101010\n"
    "1111111111111111111111111111111110000000000000000000000000000000\n"
    "1111111111111111111111111111111110000000000000000000000000000000\n"
    "1111111111111111111111111111111110000000000000000000000000000000\n"
    "1111111111111111111111111111111110000000000000000000000000000000\n"
    "1111111111111111111111111111111110000000000000000000000000000000\n"
    "1111111111111111111111111111111110000000000000000000000000000000\n"
    "1111111111111111111111111111111110000000000000000000000000000000\n"
    "1111111111111111111111111111111110000000000000000000000000000000\n"
    "1000000000000000000000000000010000000000000000000000000000000000\n"
    "                                                               0";

  auto ewah1 = make_ewah1();
  CHECK(to_string(~ewah1) == str);
}

TEST(bitwise AND EWAH) {
  auto ewah2 = make_ewah2();
  auto ewah3 = make_ewah3();
  auto str =
      "0000000000000000000000000000000000000000000000000000000000000001\n"
      "0000000000000000000000000000000000000000000000000000000000000010\n"
      "0000000000000000000000000000001010000000000000000000000000000000\n"
      "                       00000000000000000000000000000000000000000";

  auto max_size = std::max(ewah2.size(), ewah3.size());
  CHECK(to_string(ewah2 & ewah3) == str);
  CHECK((ewah2 & ewah3).size() == max_size);
  CHECK((ewah3 & ewah2).size() == max_size);

  ewah_bitstream ebs1, ebs2;
  ebs1.push_back(false);
  ebs1.append(63, true);
  ebs1.append(32, true);
  ebs2.append_block(0xfcfcfcfc, 48);

  str =
    "0000000000000000000000000000000000000000000000000000000000000001\n"
    "0000000000000000000000000000000011111100111111001111110011111100\n"
    "                                00000000000000000000000000000000";

  max_size = std::max(ebs1.size(), ebs2.size());
  CHECK(to_string(ebs1 & ebs2) == str);
  CHECK((ebs1 & ebs2).size() == max_size);
  CHECK((ebs2 & ebs1).size() == max_size);
}

TEST(bitwise OR EWAH) {
  auto ewah2 = make_ewah2();
  auto ewah3 = make_ewah3();
  auto str =
    "1000000000000000000000000000000110000000000000000000000000000010\n"
    "1001100110011001100110011001100010111111111111111111111111111111\n"
    "0000000000000000000000000000010000000000000000000000000110011001\n"
    "0000000000000000000000000000000010000000000000000000000000000000\n"
    "                       11000000000000000000000000000000000000000";

  CHECK(to_string(ewah2 | ewah3) == str);

  ewah_bitstream ebs1, ebs2;
  ebs1.append(50, true);
  ebs2.append(50, false);
  ebs2.append(50, true);

  str =
    "1000000000000000000000000000000010000000000000000000000000000000\n"
    "                            111111111111111111111111111111111111";

  CHECK(to_string(ebs1 | ebs2) == str);
}

TEST(bitwise XOR EWAH) {
  auto ewah2 = make_ewah2();
  auto ewah3 = make_ewah3();
  auto str =
    "0000000000000000000000000000000000000000000000000000000000000001\n"
    "1111111111111111111111111111111111111111111111111111111111111101\n"
    "1000000000000000000000000000000100000000000000000000000000000010\n"
    "1001100110011001100110011001100010111111111111111111111111111111\n"
    "0000000000000000000000000000010000000000000000000000000110011001\n"
    "0000000000000000000000000000000010000000000000000000000000000000\n"
    "                       11000000000000000000000000000000000000000";

  CHECK(to_string(ewah2 ^ ewah3) == str);
}

TEST(bitwise NAND EWAH) {
  auto ewah2 = make_ewah2();
  auto ewah3 = make_ewah3();
  auto str =
    "0000000000000000000000000000001100000000000000000000000000000000\n"
    "                       11000000000000000000000000000000000000000";

  CHECK(to_string(ewah2 - ewah3) == str);

  ewah_bitstream ebs1, ebs2;
  ebs1.append(100, true);
  ebs2.push_back(true);
  ebs2.append(50, false);
  ebs2.append(13, true);

  str =
    "0000000000000000000000000000000000000000000000000000000000000001\n"
    "0000000000000111111111111111111111111111111111111111111111111110\n"
    "                            111111111111111111111111111111111111";

  CHECK(to_string(ebs1 - ebs2) == str);
}

TEST(sequence iteration EWAH) {
  auto ewah1 = make_ewah1();
  auto range = ewah_bitstream::sequence_range{ewah1};

  // The first two blocks are literal.
  auto i = range.begin();
  CHECK(i->is_literal());
  CHECK(i->length == bitvector::block_width);
  CHECK(i->data == ewah1.bits().block(1));
  ++i;
  CHECK(i->is_literal());
  CHECK(i->length == bitvector::block_width);
  CHECK(i->data == ewah1.bits().block(2));

  ++i;
  CHECK(i->is_fill());
  CHECK(i->data == bitvector::all_one);
  CHECK(i->length == 3 * bitvector::block_width);

  ++i;
  CHECK(i->is_fill());
  CHECK(i->data == 0);
  CHECK(i->length == (1 << 4) * bitvector::block_width);

  ++i;
  CHECK(i->is_fill());
  CHECK(i->data == bitvector::all_one);
  CHECK(i->length == ((1ull << 32) - 1) * bitvector::block_width);

  ++i;
  CHECK(i->is_literal());
  CHECK(i->data == ewah1.bits().block(6));
  CHECK(i->length == bitvector::block_width);

  ++i;
  CHECK(i->is_literal());
  CHECK(i->data == ewah1.bits().block(7));
  CHECK(i->length == bitvector::block_width);

  ++i;
  CHECK(i->is_fill());
  CHECK(i->data == 0);
  CHECK(i->length == (1ull << (32 + 3)) * 64);

  ++i;
  CHECK(i->is_literal());
  CHECK(i->data == 1);
  CHECK(i->length == 1);

  CHECK(++i == range.end());
}

TEST(block appending(EWAH)) {
  ewah_bitstream ebs;
  ebs.append(10, true);
  ebs.append_block(0xf00);
  CHECK(ebs.size() == 10 + bitvector::block_width);
  CHECK(! ebs[17]);
  CHECK(ebs[18]);
  CHECK(ebs[19]);
  CHECK(ebs[20]);
  CHECK(ebs[21]);
  CHECK(! ebs[22]);

  ebs.append(2048, true);
  ebs.append_block(0xff00);

  auto str =
    "0000000000000000000000000000000000000000000000000000000000000010\n"
    "0000000000000000000000000000000000000000001111000000001111111111\n"
    "1111111111111111111111111111111111111111111111111111110000000000\n"
    "1000000000000000000000000000111110000000000000000000000000000001\n"
    "0000000000000000000000000000000000000011111111000000001111111111\n"
    "                                                      0000000000";

  CHECK(to_string(ebs) == str);
}

TEST(polymorphic iteration) {
  bitstream bs{null_bitstream{}};
  bs.push_back(true);
  bs.append(10, false);
  bs.append(2, true);

  auto i = bs.begin();
  CHECK(*i == 0);
  CHECK(*++i == 11);
  CHECK(*++i == 12);
  CHECK(++i == bs.end());

  bs = bitstream{ewah_bitstream{}};
  bs.push_back(false);
  bs.push_back(true);
  bs.append(421, false);
  bs.push_back(true);
  bs.push_back(true);

  i = bs.begin();
  CHECK(*i == 1);
  CHECK(*++i == 423);
  CHECK(*++i == 424);
  CHECK(++i == bs.end());
}

TEST(sequence iteration NULL) {
  null_bitstream nbs;
  nbs.push_back(true);
  nbs.push_back(false);
  nbs.append(62, true);
  nbs.append(320, false);
  nbs.append(512, true);

  auto range = null_bitstream::sequence_range{nbs};
  auto i = range.begin();
  CHECK(i != range.end());
  CHECK(i->offset == 0);
  CHECK(i->is_literal());
  CHECK(i->data == (bitvector::all_one & ~2));

  ++i;
  CHECK(i != range.end());
  CHECK(i->offset == 64);
  CHECK(i->is_fill());
  CHECK(i->data == 0);
  CHECK(i->length == 320);

  ++i;
  CHECK(i != range.end());
  CHECK(i->offset == 64 + 320);
  CHECK(i->is_fill());
  CHECK(i->data == bitvector::all_one);
  CHECK(i->length == 512);

  CHECK(++i == range.end());
}

TEST(pop count NULL) {
  null_bitstream bs;
  bs.push_back(true);
  bs.push_back(false);
  CHECK(bs.count() == 1);
  bs.append(62, true);
  bs.append(320, false);
  bs.append(512, true);
  bs.append(47, false);
  CHECK(bs.count() == 575);
}

TEST(pop count EWAH) {
  ewah_bitstream bs;
  bs.push_back(true);
  bs.push_back(false);
  CHECK(bs.count() == 1);
  bs.append(62, true);
  CHECK(bs.count() == 63);
  bs.append(320, false);
  CHECK(bs.count() == 63);
  bs.append(512, true);
  bs.append(47, false);
  CHECK(bs.count() == 575);
}

namespace {

template <typename Bitstream>
void test_append() {
  Bitstream bs1, bs2;
  bs1.push_back(true);
  bs1.push_back(false);
  bs1.append(4444, true);
  auto size = bs1.size();
  CHECK(size == 4446);

  bs2.append(500, false);
  bs2.append(20, true);
  CHECK(bs2.size() == 520);

  bs1.append(bs2);
  CHECK(bs1.size() == size + bs2.size());
  CHECK(bs1.size() == 4966);
  CHECK(bs1[size + 500]);
  CHECK(bs1[size + 519]);

  size = bs2.size();
  bs2.append(bs1);
  CHECK(bs2.size() == size + bs1.size());
  CHECK(bs2[size]); // first of bs1
  CHECK(!bs2[size + 1]);
  CHECK(bs2[size + 2]);
  CHECK(bs2[size + 2 + 4443]);
}

} // namespace <anonymous>

TEST(append_NULL) {
  test_append<null_bitstream>();
}

TEST(append_EWAH) {
  test_append<ewah_bitstream>();
}
