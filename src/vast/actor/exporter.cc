#include <caf/all.hpp>

#include "vast/event.h"
#include "vast/logger.h"
#include "vast/actor/exporter.h"
#include "vast/concept/printable/stream.h"
#include "vast/concept/printable/to_string.h"
#include "vast/concept/printable/vast/event.h"
#include "vast/concept/printable/vast/error.h"
#include "vast/concept/printable/vast/expression.h"
#include "vast/concept/printable/vast/time.h"
#include "vast/expr/evaluator.h"
#include "vast/expr/resolver.h"
#include "vast/util/assert.h"

using namespace caf;

namespace vast {

exporter::exporter(expression ast, query_options opts)
  : default_actor{"exporter"},
    id_{uuid::random()},
    ast_{std::move(ast)},
    opts_{opts} {
  auto incorporate_hits = [=](bitstream_type const& hits) {
    VAST_DEBUG(this, "got index hit covering", '[' << hits.find_first() << ','
                                                   << (hits.find_last() + 1)
                                                   << ')');
    VAST_ASSERT(!hits.all_zeros());           // Empty hits are useless.
    VAST_ASSERT((hits & hits_).count() == 0); // So are duplicate hits.
    total_hits_ += hits.count();
    hits_ |= hits;
    unprocessed_ = hits_ - processed_;
    prefetch();
  };

  auto handle_progress =
    [=](progress_atom, uint64_t remaining, uint64_t total) {
        progress_ = (total - double(remaining)) / total;
        for (auto& s : sinks_)
          send(s, id_, progress_atom::value, progress_, total_hits_);
    };

  auto handle_down = [=](down_msg const& msg) {
    VAST_DEBUG("got DOWN from", msg.source);
    auto a = actor_cast<actor>(msg.source);
    if (archives_.erase(a) > 0)
      return;
    if (indexes_.erase(a) > 0)
      return;
    if (sinks_.erase(a) > 0)
      return;
  };

  auto complete = [=] {
    auto runtime = time::snapshot() - start_time_;
    for (auto& s : sinks_)
      send(s, id_, done_atom::value, runtime);
    VAST_INFO(this, "took", runtime, "for:", ast_);
    quit(exit::done);
  };

  init_ = {
    handle_down,
    [=](put_atom, archive_atom, actor const& a) {
      VAST_DEBUG(this, "registers archive", a);
      monitor(a);
      archives_.insert(a);
    },
    [=](put_atom, index_atom, actor const& a) {
      VAST_DEBUG(this, "registers index", a);
      monitor(a);
      indexes_.insert(a);
    },
    [=](put_atom, sink_atom, actor const& a) {
      VAST_DEBUG(this, "registers sink", a);
      monitor(a);
      sinks_.insert(a);
    },
    [=](run_atom) {
      if (archives_.empty()) {
        VAST_ERROR(this, "cannot run without archive(s)");
        quit(exit::error);
        return;
      }
      if (indexes_.empty()) {
        VAST_ERROR(this, "cannot run without index(es)");
        quit(exit::error);
        return;
      }
      for (auto& i : indexes_) {
        VAST_DEBUG(this, "sends query to index" << i);
        send(i, ast_, opts_, this);
      }
      become(idle_);
      start_time_ = time::snapshot();
    }
  };

  idle_ = {
    handle_down,
    handle_progress,
    [=](actor const& task) {
      VAST_TRACE(this, "received task from index");
      task_ = task;
      send(task_, subscriber_atom::value, this);
    },
    [=](bitstream_type const& hits) {
      incorporate_hits(hits);
      if (inflight_) {
        VAST_DEBUG(this, "becomes waiting (pending in-flight chunks)");
        become(waiting_);
      }
    },
    [=](done_atom, time::extent runtime, expression const&) // from INDEX
    {
      VAST_VERBOSE(this, "completed index interaction in", runtime);
      complete();
    }
  };

  waiting_ = {
    handle_down,
    handle_progress,
    incorporate_hits,
    [=](chunk const& chk) {
      VAST_DEBUG(this, "got chunk [" << chk.base() << ','
                                     << (chk.base() + chk.events()) << ")");
      inflight_ = false;
      chunk_ = chk;
      VAST_ASSERT(!reader_);
      reader_ = std::make_unique<chunk::reader>(chunk_);
      VAST_DEBUG(this, "becomes extracting");
      become(extracting_);
      if (pending_ > 0)
        send(this, extract_atom::value);
      prefetch();
    }
  };

  extracting_ = {
    handle_down, handle_progress, incorporate_hits,
    [=](stop_atom) {
      VAST_DEBUG(this, "got request to drain and terminate");
      draining_ = true;
    },
    [=](extract_atom, uint64_t requested) {
      auto show_events = [](uint64_t n) -> std::string {
        return n == max_events ? "all" : to_string(n);
      };
      if (requested == 0)
        requested = max_events;
      VAST_DEBUG(this, "got request to extract", show_events(requested),
                 "events (" << to_string(pending_), "pending)");
      if (pending_ == max_events) {
        VAST_WARN(this, "ignores extract request, already getting all events");
        return;
      }
      if (pending_ > 0) {
        if (pending_ > max_events - requested)
          pending_ = max_events;
        else
          pending_ += requested;
        VAST_VERBOSE(this, "raises pending events to", show_events(pending_),
                     "events");
        return;
      }
      pending_ = std::min(max_events, requested);
      VAST_DEBUG(this, "extracts", show_events(pending_), "events");
      send(this, extract_atom::value);
    },
    [=](extract_atom) {
      VAST_ASSERT(pending_ > 0);
      VAST_ASSERT(reader_);
      // We construct a new mask for each extraction request, because hits may
      // continuously update in every state.
      bitstream_type mask{chunk_.meta().ids};
      mask &= unprocessed_;
      VAST_ASSERT(mask.count() > 0);
      // Go through the current chunk and perform a candidate check for each
      // hit, relaying event to the sink on success.
      auto extracted = uint64_t{0};
      auto last = event_id{0};
      for (auto id : mask) {
        last = id;
        auto e = reader_->read(id);
        if (e) {
          auto& ast = expressions_[e->type()];
          if (is<none>(ast)) {
            auto t = visit(expr::schema_resolver{e->type()}, ast_);
            if (!t) {
              VAST_ERROR(this, "failed to resolve", ast_ << ',', t.error());
              quit(exit::error);
              return;
            }
            ast = visit(expr::type_resolver{e->type()}, *t);
            VAST_DEBUG(this, "resolved AST for type", e->type() << ':', ast);
          }
          if (visit(expr::event_evaluator{*e}, ast)) {
            auto msg = make_message(id_, std::move(*e));
            for (auto& s : sinks_)
              send(s, msg);
            ++total_results_;
            if (++extracted == pending_)
              break;
          } else {
            VAST_WARN(this, "ignores false positive:", *e);
          }
        } else {
          if (e.empty())
            VAST_ERROR(this, "failed to extract event", id);
          else
            VAST_ERROR(this, "failed to extract event", id << ':', e.error());
          quit(exit::error);
          return;
        }
      }
      pending_ -= extracted;
      bitstream_type partial{last + 1, true};
      partial &= mask;
      processed_ |= partial;
      unprocessed_ -= partial;
      mask -= partial;
      VAST_DEBUG(this, "extracted", extracted,
                 "events (" << partial.count() << '/' << mask.count(),
                 "processed/remaining hits in current chunk)");
      VAST_ASSERT(!mask.empty());
      if (pending_ == 0 && draining_) {
        VAST_DEBUG(this, "stops after having drained all pending events");
        complete();
      }
      if (!mask.all_zeros()) {
        // We continue extracting until we have processed all requested
        // events.
        if (pending_ > 0)
          send(this, current_message());
        return;
      }
      reader_.reset();
      chunk_ = {};
      if (inflight_) {
        VAST_DEBUG(this, "becomes waiting (pending in-flight chunks)");
        become(waiting_);
      } else {
        // No in-flight chunk implies that we have no more unprocessed hits,
        // because arrival of new hits automatically triggers prefetching.
        VAST_ASSERT(!unprocessed_.empty());
        VAST_ASSERT(unprocessed_.all_zeros());
        VAST_DEBUG(this, "becomes idle (no in-flight chunks)");
        become(idle_);
        if (progress_ == 1.0 && unprocessed_.count() == 0)
          complete();
      }
    }
  };
}

void exporter::on_exit() {
  archives_.clear();
  indexes_.clear();
  sinks_.clear();
}

behavior exporter::make_behavior() {
  return init_;
}

void exporter::prefetch() {
  if (inflight_)
    return;
  if (chunk_.events() == 0) {
    auto last = unprocessed_.find_last();
    if (last != bitstream_type::npos) {
      VAST_DEBUG(this, "prefetches chunk for ID", last);
      for (auto& a : archives_)
        send(a, last);
      inflight_ = true;
    }
  } else {
    VAST_DEBUG(this, "looks for next unprocessed ID after",
               chunk_.meta().ids.find_last());
    auto next = unprocessed_.find_next(chunk_.meta().ids.find_last());
    if (next != bitstream_type::npos) {
      VAST_DEBUG(this, "prefetches chunk for next ID", next);
      for (auto& a : archives_)
        send(a, next);
      inflight_ = true;
    } else {
      auto prev = unprocessed_.find_prev(chunk_.meta().ids.find_first());
      if (prev != bitstream_type::npos) {
        VAST_DEBUG(this, "prefetches chunk for previous ID", prev);
        for (auto& a : archives_)
          send(a, prev);
        inflight_ = true;
      }
    }
  }
}

} // namespace vast
