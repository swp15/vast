#ifndef VAST_DETAIL_CAF_PROFILING_COORDINATOR_H
#define VAST_DETAIL_CAF_PROFILING_COORDINATOR_H

#include <sys/resource.h>   // getrusage
#include <chrono>
#include <fstream>
#include <unordered_map>
#include <caf/policy/work_stealing.hpp>

namespace vast {
namespace detail {

/// A coordinator which keeps fine-grained profiling state about its workers
/// and their jobs.
template <typename Policy>
class caf_profiling_coordinator : public caf::scheduler::coordinator<Policy>
{
  struct context
  {
    std::chrono::steady_clock::duration last_time;
    std::chrono::microseconds last_usr;
    std::chrono::microseconds last_sys;
    long last_rss;
    std::chrono::steady_clock::duration all_time =
      std::chrono::steady_clock::duration::zero();
    std::chrono::microseconds all_usr = std::chrono::microseconds::zero();
    std::chrono::microseconds all_sys = std::chrono::microseconds::zero();
    long all_rss = 0;
  };

  class measurement
  {
  public:
    measurement()
      : now_{std::chrono::steady_clock::now()}
    {
      ::getrusage(RUSAGE_THREAD, &ru_);
    }

    void reset(context& ctx) const
    {
      ctx.last_time = now_.time_since_epoch();
      ctx.last_usr = to_usec(ru_.ru_utime);
      ctx.last_sys = to_usec(ru_.ru_stime);
      ctx.last_rss = ru_.ru_maxrss;
    }

    void update(context& ctx) const
    {
      ctx.all_time += now_.time_since_epoch() - ctx.last_time;
      ctx.all_usr += to_usec(ru_.ru_utime) - ctx.last_usr;
      ctx.all_sys += to_usec(ru_.ru_stime) - ctx.last_sys;
      ctx.all_rss += ru_.ru_maxrss - ctx.last_rss;
    }

    std::chrono::steady_clock::time_point timestamp() const
    {
      return now_;
    }

  private:
    static std::chrono::microseconds to_usec(timeval const& tv)
    {
      return std::chrono::seconds(tv.tv_sec)
        + std::chrono::microseconds(tv.tv_usec);
    }

    std::chrono::steady_clock::time_point now_;
    ::rusage ru_;
  };

public:
  using super = caf::scheduler::coordinator<Policy>;

  caf_profiling_coordinator(std::string const& filename,
      size_t nw = std::max(std::thread::hardware_concurrency(), 4u),
      size_t mt = std::numeric_limits<size_t>::max())
    : super{nw, mt},
      file_{filename},
      system_start_{std::chrono::system_clock::now()},
      steady_start_{std::chrono::steady_clock::now()}
  {
  }

  void initialize() override
  {
    super::initialize();
    if (! file_)
      throw std::runtime_error{"failed to open caf profiler file"};;
    file_.flags(std::ios::left);
    file_
      << std::setw(18) << "clock"
      << std::setw(18) << "time"
      << std::setw(14) << "usr"
      << std::setw(14) << "sys"
      << std::setw(14) << "rss"
      << std::setw(14) << "cum_usr"
      << std::setw(14) << "cum_sys"
      << std::setw(14) << "cum_rss"
      << std::endl;
  }

  void start_measuring(size_t worker, caf::resumable* job)
  {
    measurement m;
    m.reset(workers_[worker]);
    if (id_of(job) == 0)
      return;
    m.reset(jobs_[job]);
  }

  void stop_measuring(size_t worker, caf::resumable* job)
  {
    measurement m;
    if (id_of(job) != 0)
      m.update(jobs_[job]);
    auto& wrk_ctx = workers_[worker];
    m.update(wrk_ctx);
    if (m.timestamp() - last_ < resolution_)
      return;
    last_ = m.timestamp();
    file_ << "worker#" << worker << '\t';
    dump(m.timestamp(), wrk_ctx);
  }

  void record_job(caf::resumable* job)
  {
    auto aid = id_of(job);
    if (aid == 0)
      return;
    auto i = jobs_.find(job);
    assert(i != jobs_.end());
    file_ << "actor#" << aid << '\t';
    dump(std::chrono::steady_clock::now(), i->second);
    jobs_.erase(i);
  }

private:
  static caf::actor_id id_of(caf::resumable* job)
  {
    auto ptr = dynamic_cast<caf::abstract_actor*>(job);
    return ptr ? ptr->id() : 0;
  }

  void dump(std::chrono::steady_clock::time_point now, context const& ctx)
  {
    auto wallclock = system_start_ + (now - steady_start_);
    file_
      << std::fixed
      << std::setw(18) << wallclock.time_since_epoch().count()
      << std::setw(18) << ctx.last_time.count()
      << std::setw(14) << ctx.last_usr.count()
      << std::setw(14) << ctx.last_sys.count()
      << std::setw(14) << ctx.last_rss
      << std::setw(18) << ctx.all_time.count()
      << std::setw(14) << ctx.all_usr.count()
      << std::setw(14) << ctx.all_sys.count()
      << std::setw(14) << ctx.all_rss
      << std::endl;
  }

  std::ofstream file_;
  std::unordered_map<size_t, context> workers_;
  std::unordered_map<caf::resumable*, context> jobs_;
  std::chrono::system_clock::time_point system_start_;
  std::chrono::steady_clock::time_point steady_start_;
  std::chrono::milliseconds resolution_{1000}; // TODO: make configurable
  std::chrono::steady_clock::time_point last_;
};

/// An enhancement of CAF's work-stealing policy which records fine-grained
/// resource utiliziation for worker threads and actors in the parent
/// coordinator of the workers.
struct profiled_work_stealing : caf::policy::work_stealing
{
  template <typename Worker>
  void before_resume(Worker* worker, caf::resumable* job)
  {
    worker->parent()->start_measuring(worker->id, job);
  }

  template <typename Worker>
  void after_resume(Worker* worker, caf::resumable* job)
  {
    worker->parent()->stop_measuring(worker->id, job);
  }

  template <typename Worker>
  void after_completion(Worker* worker, caf::resumable* job)
  {
    worker->parent()->record_job(job);
  }
};

} // namespace detail
} // namespace vast

#endif
