#include <algorithm>
#include <iostream>
#include <limits>
#include <string>
#include <thread>
#include <vector>

#include <caf/all.hpp>
#include <caf/experimental/whereis.hpp>
#include <caf/io/all.hpp>

#include "vast/aliases.h"
#include "vast/announce.h"
#include "vast/banner.h"
#include "vast/filesystem.h"
#include "vast/key.h"
#include "vast/logger.h"
#include "vast/uuid.h"
#include "vast/actor/accountant.h"
#include "vast/actor/atoms.h"
#include "vast/actor/exit.h"
#include "vast/actor/sink/spawn.h"
#include "vast/actor/source/spawn.h"
#include "vast/concept/printable/to_string.h"
#include "vast/concept/printable/vast/error.h"
#include "vast/concept/printable/vast/uuid.h"
#include "vast/detail/adjust_resource_consumption.h"
#include "vast/util/endpoint.h"
#include "vast/util/flat_set.h"
#include "vast/util/string.h"

using namespace vast;
using namespace std::string_literals;

int main(int argc, char* argv[]) {
  if (!detail::adjust_resource_consumption())
    return 1;
  // Locate command in command line.
  std::vector<std::string> commands = {
    "connect",
    "disconnect",
    "export",
    "import",
    "quit",
    "peer",
    "send",
    "show",
    "spawn",
    "stop"
  };
  std::vector<std::string> command_line(argv + 1, argv + argc);
  auto cmd = std::find_first_of(command_line.begin(), command_line.end(),
                                commands.begin(), commands.end());
  // Parse and validate command line.
  auto log_level = 3;
  auto dir = "."s;
  auto endpoint = ""s;
  auto host = "127.0.0.1"s;
  auto port = uint16_t{42000};
  auto messages = std::numeric_limits<size_t>::max();
  auto threads = std::thread::hardware_concurrency();
  auto r = caf::message_builder(command_line.begin(), cmd).extract_opts({
    {"dir,d", "directory for logs and client state", dir},
    {"endpoint,e", "node endpoint", endpoint},
    {"log-level,l", "verbosity of console and/or log file", log_level},
    {"messages,m", "maximum messages per CAF scheduler invocation", messages},
    {"threads,t", "number of worker threads in CAF scheduler", threads},
    {"version,v", "print version and exit"}
  });
  if (! r.error.empty()) {
    std::cerr << r.error << std::endl;
    return 1;
  }
  if (r.opts.count("version") > 0) {
    std::cout << VAST_VERSION << std::endl;
    return 0;
  }
  if (r.opts.count("help") > 0) {
    std::cout << banner() << "\n\n" << r.helptext;
    return 0;
  }
  if (r.opts.count("endpoint") > 0
      && !util::parse_endpoint(endpoint, host, port)) {
    std::cout << "invalid endpoint: " << endpoint << std::endl;
    return 1;
  }
  if (!r.remainder.empty()) {
    auto invalid_cmd = r.remainder.get_as<std::string>(0);
    std::cerr << "invalid command: " << invalid_cmd << std::endl;
    return 1;
  }
  if (cmd == command_line.end()) {
    std::cerr << "missing command" << std::endl;
    return 1;
  }
  // Initialize logger.
  auto colorized = true;
  auto verbosity = static_cast<logger::level>(log_level);
  if (!logger::console(verbosity, colorized)) {
    std::cerr << "failed to initialize logger console backend" << std::endl;
    return 1;
  }
  if (!logger::file(logger::quiet)) {
    std::cerr << "failed to reset logger file backend" << std::endl;
    return 1;
  }
  // Adjust scheduler parameters.
  if (r.opts.count("threads") || r.opts.count("messages"))
    caf::set_scheduler<>(threads, messages);
  // Enable direct connections.
  VAST_VERBOSE("enabling direct connection optimization");
  auto cfg = caf::experimental::whereis(caf::atom("ConfigServ"));
  caf::anon_send(cfg, put_atom::value, "global.enable-automatic-connections",
                 caf::make_message(true));
  // Establish connection to remote node.
  auto guard = caf::detail::make_scope_guard([] {
    caf::shutdown();
    logger::destruct();
  });
  announce_types();
  caf::actor node;
  try {
    VAST_VERBOSE("connecting to", host << ':' << port);
    node = caf::io::remote_actor(host.c_str(), port);
  } catch (caf::network_error const& e) {
    VAST_ERROR("failed to connect to", host << ':' << port);
    return 1;
  }
  // Process commands.
  caf::scoped_actor self;
  auto accounting_log = path(dir) / "accounting.log";
  if (*cmd == "import") {
    // 1. Spawn a SOURCE.
    caf::message_builder mb;
    auto i = cmd + 1;
    while (i != command_line.end())
      mb.append(*i++);
    auto src = source::spawn(mb.to_message());
    if (!src) {
      VAST_ERROR("failed to spawn source:", src.error());
      return 1;
    }
    auto source_guard = caf::detail::make_scope_guard(
      [=] { anon_send_exit(*src, exit::kill); });
    auto acc = self->spawn<accountant<uint64_t>>(accounting_log);
    acc->link_to(*src);
    self->send(*src, put_atom::value, accountant_atom::value, acc);
    // 2. Find all IMPORTERs to load-balance across them.
    std::vector<caf::actor> importers;
    self->sync_send(node, store_atom::value, list_atom::value,
                    key::str("actors")).await(
      [&](std::map<std::string, caf::message>& m) {
        for (auto& p : m)
          p.second.apply({
            [&](caf::actor const& a, std::string const& type) {
              VAST_ASSERT(a != caf::invalid_actor);
              if (type == "importer")
                importers.push_back(a);
            }
          });
      }
    );
    if (importers.empty()) {
      VAST_ERROR("no importers found");
      return 1;
    }
    // 3. Connect SOURCE and IMPORTERs.
    for (auto& imp : importers) {
      VAST_ASSERT(imp != caf::invalid_actor);
      VAST_DEBUG("connecting source with importer", imp);
      self->send(*src, put_atom::value, sink_atom::value, imp);
    }
    // 4. Run the SOURCE.
    VAST_DEBUG("running source");
    self->send(*src, run_atom::value);
    source_guard.disable();
  } else if (*cmd == "export") {
    if (cmd + 1 == command_line.end()) {
      VAST_ERROR("missing sink format");
      return 1;
    } else if (cmd + 2 == command_line.end()) {
      VAST_ERROR("missing query arguments");
      return 1;
    }
    // 1. Spawn a SINK.
    auto snk = sink::spawn(caf::make_message(*(cmd + 1)));
    if (!snk) {
      VAST_ERROR("failed to spawn sink:", snk.error());
      return 1;
    }
    auto sink_guard = caf::detail::make_scope_guard(
      [snk = *snk] { anon_send_exit(snk, exit::kill); });
    auto acc = self->spawn<accountant<uint64_t>>(accounting_log);
    acc->link_to(*snk);
    self->send(*snk, put_atom::value, accountant_atom::value, acc);
    // 2. For each node, spawn an (auto-connected) EXPORTER and connect it to
    // the sink.
    std::vector<caf::actor> nodes;
    self->sync_send(node, store_atom::value, list_atom::value,
                    key::str("nodes")).await(
      [&](std::map<std::string, caf::message> const& m) {
        for (auto& p : m)
          nodes.push_back(p.second.get_as<caf::actor>(0));
      }
    );
    VAST_ASSERT(!nodes.empty());
    for (auto n : nodes) {
      // Spawn remote exporter.
      caf::message_builder mb;
      auto label = "exporter-" + to_string(uuid::random()).substr(0, 7);
      mb.append("spawn");
      mb.append("-l");
      mb.append(label);
      mb.append("exporter");
      mb.append("-a");
      auto i = cmd + 2;
      mb.append(*i++);
      while (i != command_line.end())
        mb.append(*i++);
      self->send(n, mb.to_message());
      VAST_DEBUG("created", label, "at node" << node);
    }
    // 3. Wait until the remote NODE returns the EXPORTERs so that we can
    // monitor them and connect them with our local SINK.
    auto failed = false;
    auto early_finishers = 0u;
    util::flat_set<caf::actor> exporters;
    self->do_receive(
      [&](caf::actor const& exporter) {
        exporters.insert(exporter);
        self->monitor(exporter);
        self->send(exporter, put_atom::value, sink_atom::value, *snk);
        VAST_DEBUG("running exporter");
        self->send(exporter, stop_atom::value);
        self->send(exporter, run_atom::value);
      },
      [&](caf::down_msg const& msg) {
        ++early_finishers;
        exporters.erase(caf::actor_cast<caf::actor>(msg.source));
      },
      [&](error const& e) {
        failed = true;
        VAST_ERROR("failed to spawn exporter on node"
                   << self->current_sender() << ':', e);
      },
      caf::others >> [&] {
        failed = true;
        VAST_ERROR("got unexpected message from node"
                   << self->current_sender() << ':',
                   caf::to_string(self->current_message()));
      }
    ).until([&] {
      return early_finishers + exporters.size() == nodes.size() || failed;
    });
    if (failed) {
      for (auto exporter : exporters)
        self->send_exit(exporter, exit::error);
      return 1;
    }
    // 4. Wait for all EXPORTERs to terminate. Thereafter we can shutdown the
    // SINK and finish.
    if (!exporters.empty()) {
      self->do_receive(
        [&](caf::down_msg const& msg) {
          exporters.erase(caf::actor_cast<caf::actor>(msg.source));
          VAST_DEBUG("got DOWN from exporter" << msg.source << ',',
                     "remaining:", exporters.size());
        },
        caf::others >> [&] {
          failed = true;
          VAST_ERROR("got unexpected message from node"
                       << self->current_sender() << ':',
                     caf::to_string(self->current_message()));
        }
      ).until([&] { return exporters.size() == 0 || failed; });
    }
    if (failed)
      return 1;
    sink_guard.disable();
    self->send_exit(*snk, exit::done);
  } else {
    // Only "import" and "export" are local commands, the remote node executes
    // all other ones.
    auto args = std::vector<std::string>(cmd + 1, command_line.end());
    caf::message_builder mb;
    mb.append(*cmd);
    for (auto& a : args)
      mb.append(std::move(a));
    auto cmd_line = *cmd + util::join(args, " ");
    auto exit_code = 0;
    VAST_DEBUG("sending command:", to_string(mb.to_message()));
    self->sync_send(node, mb.to_message()).await(
      [&](ok_atom) {
        VAST_VERBOSE("successfully executed command:", cmd_line);
      },
      [&](caf::actor const&) {
        VAST_VERBOSE("successfully executed command:", cmd_line);
      },
      [&](std::string const& str) {
        VAST_VERBOSE("successfully executed command:", cmd_line);
        std::cout << str << std::endl;
      },
      [&](error const& e) {
        VAST_ERROR("failed to execute command:", cmd_line);
        VAST_ERROR(e);
        exit_code = 1;
      },
      caf::others >> [&] {
        auto msg = to_string(self->current_message());
        VAST_ERROR("got unexpected reply:", msg);
        exit_code = 1;
      }
    );
    if (exit_code != 0)
      return exit_code;
  }
  self->await_all_other_actors_done();
  return 0;
}
