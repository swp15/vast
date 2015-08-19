#include <iostream>

#include <caf/message_builder.hpp>

#include "vast/filesystem.h"
#include "vast/io/algorithm.h"
#include "vast/io/file_stream.h"
#include "vast/util/posix.h"

using namespace caf;
using namespace std;
using namespace std::string_literals;
using namespace vast;
using namespace vast::io;

int main(int argc, char** argv) {
  auto usage = "usage: dscat [-lrw] <uds> [file]";
  auto r = message_builder{argv + 1, argv + argc}.extract_opts({
    {"listen,l", "listen on <uds> and serve <file>"},
    {"write,w", "open <file> for writing"},
    {"read,r", "open <file> for reading"}
  });
  if (r.remainder.size() > 2) {
    cerr << usage << endl;
    return 1;
  }
  if (r.remainder.empty()) {
    cerr << usage << "\n\n" << r.helptext;
    return 1;
  }
  auto& uds_name = r.remainder.get_as<std::string>(0);
  auto filename
    = r.remainder.size() == 2 ? r.remainder.get_as<std::string>(1) : "-";
  auto reading = r.opts.count("read") > 0;
  auto writing = r.opts.count("write") > 0;
  if (!reading && !writing) {
    cerr << "need to specify either read (-r) or write (-w) mode" << endl;
    return 1;
  }
  if (reading && writing && filename == "-") {
    cerr << "cannot open standard input or output in read/write mode" << endl;
    return 1;
  }
  if (r.opts.count("listen") > 0) {
    cerr << "listening on " << uds_name << " (";
    if (reading)
      cerr << 'R';
    if (writing)
      cerr << 'W';
    cerr << ") to serve " << filename << endl;
    auto uds = util::unix_domain_socket::accept(uds_name);
    if (!uds) {
      cerr << "failed to accept connection" << endl;
      return -1;
    }
    file f{filename};
    auto mode = file::invalid;
    if (reading && writing)
      mode = file::read_write;
    else if (reading)
      mode = file::read_only;
    else if (writing)
      mode = file::write_only;
    if (!f.open(mode)) {
      cerr << "failed to open file " << filename << endl;
      return 1;
    }
    cerr << "sending file descriptor " << f.handle() << endl;
    if (!uds.send_fd(f.handle())) {
      cerr << "failed to send file descriptor" << endl;
      return 1;
    }
  } else {
    cerr << "connecting to " << uds_name << endl;
    auto uds = util::unix_domain_socket::connect(uds_name);
    if (!uds) {
      cerr << "failed to connect" << endl;
      return 1;
    }
    cerr << "receiving file descriptor " << endl;
    auto fd = uds.recv_fd();
    if (fd < 0) {
      cerr << "failed to receive file descriptor" << endl;
      return 1;
    }
    cerr << "dumping contents\n" << endl;
    file_input_stream is{fd, close_on_destruction};
    file_output_stream os{"-"};
    copy(is, os);
  }
  return 0;
}
