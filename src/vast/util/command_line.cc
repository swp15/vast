#include "vast/util/command_line.h"

namespace vast {
namespace util {

bool command_line::mode_add(std::string name,
                            std::string desc,
                            std::string prompt,
                            std::string history_file)
{
  if (modes_.count(name))
    return false;
  auto m = std::make_shared<mode>(
      std::move(name), std::move(desc),
      std::move(prompt), std::move(history_file));
  modes_.emplace(m->name, m);
  return true;
}

bool command_line::mode_rm(std::string const& name)
{
  if (! modes_.count(name))
    return false;
  modes_.erase(name);
  return true;
}

bool command_line::mode_push(std::string const& mode)
{
  if (! modes_.count(mode))
    return false;
  mode_stack_.push_back(modes_[mode]);
  return true;
}

bool command_line::mode_pop()
{
  if (mode_stack_.empty())
    return false;
  mode_stack_.pop_back();
  return true;
}

bool command_line::cmd_add(std::string const& mode, std::string cmd, callback f)
{
  if (! modes_.count(mode))
    return false;
  auto& m = *modes_[mode];
  if (m.callbacks.count(cmd))
    return false;
  m.el.complete(cmd);
  m.callbacks.emplace(std::move(cmd), std::move(f));
  return true;
}

bool command_line::cmd_rm(std::string const& mode, std::string const& cmd)
{
  if (! modes_.count(mode))
    return false;
  auto& m = *modes_[mode];
  if (! m.callbacks.count(cmd))
    return false;
  m.callbacks.erase(cmd);
  return true;
}

bool command_line::on_unknown_command(std::string const& mode, callback f)
{
  if (! modes_.count(mode))
    return false;
  auto& m = *modes_[mode];
  m.unknown_command = f;
  return true;
}

bool command_line::append_to_history(std::string const& entry)
{
  if (mode_stack_.empty())
    return false;
  mode_stack_.back()->hist.enter(entry);
  mode_stack_.back()->hist.save();
  return true;
}

bool command_line::process(bool& callback_result)
{
  if (mode_stack_.empty())
    return false;
  auto current = mode_stack_.back();
  current->el.reset();  // Fixes TTY weirdness when switching between modes.
  std::string cmd;
  if (! current->el.get(cmd))
    return false;
  // Trim string.
  auto first_non_ws = cmd.find_first_not_of(" \t");
  auto last_non_ws = cmd.find_last_not_of(" \t");
  if (first_non_ws != std::string::npos)
    cmd = cmd.substr(first_non_ws, last_non_ws - first_non_ws + 1);
  auto space = cmd.find(' ');
  auto key = cmd.substr(0, space);
  if (! current->callbacks.count(key))
  {
    if (! current->unknown_command)
      return false;
    callback_result = current->unknown_command(std::move(cmd));
    return true;
  }
  auto args = space == std::string::npos ? cmd : cmd.substr(++space);
  callback_result = current->callbacks[key](std::move(args));
  current->hist.enter(cmd);
  current->hist.save();
  return true;
}

bool command_line::get(char& c)
{
  return mode_stack_.empty() ? false : mode_stack_.back()->el.get(c);
}

command_line::mode::mode(std::string name,
                         std::string desc,
                         std::string prompt,
                         std::string filename)
  : name{std::move(name)},
    description{std::move(desc)},
    hist{1000, true, std::move(filename)}
{
  el.source();
  el.set(hist);
  if (! prompt.empty())
    el.set(editline::prompt{std::move(prompt)});
}

} // namespace util
} // namespace vast
