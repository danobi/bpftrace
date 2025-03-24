#include "location.h"

#include <sstream>

#include "ast/context.h"

namespace bpftrace::ast {

Location::Location(location loc, std::shared_ptr<ASTSource> source)
    : line_range_(loc.begin.line, loc.end.line),
      column_range_(loc.begin.column, loc.end.column),
      source_(std::move(source))
{
}

std::string Location::filename() const
{
  if (source_) {
    return source_->filename;
  }
  return "";
}

bool Location::contains(const Location &other) const
{
  // Different sources means no containment
  if (filename() != other.filename())
    return false;

  // Check line range containment
  if (line_range_.first > other.line_range_.first ||
      line_range_.second < other.line_range_.second)
    return false;

  // If lines are exactly at boundaries, check column containment
  if (line_range_.first == other.line_range_.first &&
      column_range_.first > other.column_range_.first)
    return false;

  if (line_range_.second == other.line_range_.second &&
      column_range_.second < other.column_range_.second)
    return false;

  return true;
}

std::string Location::source_location() const
{
  std::stringstream ss;
  if (source_) {
    ss << source_->filename << ":";
  }
  if (line_range_.first != line_range_.second) {
    ss << line_range_.first << "-" << line_range_.second;
    return ss.str();
  }
  ss << line_range_.first << ":";
  ss << column_range_.first << "-" << column_range_.second;
  return ss.str();
}

std::vector<std::string> Location::source_context() const
{
  std::vector<std::string> result;

  // Is there source available?
  if (!source_ || line_range_.first == 0) {
    return result;
  }

  // Multi-lines just include all context.
  if (line_range_.first != line_range_.second) {
    assert(line_range_.first < line_range_.second);
    for (unsigned int i = line_range_.first; i <= line_range_.second; i++) {
      assert(i <= source_->lines_.size());
      result.push_back(source_->lines_[i - 1]);
    }
    return result;
  }

  // Single line includes just the relevant context.
  if (line_range_.first > source_->lines_.size()) {
    return result; // Nothing available.
  }
  auto &srcline = source_->lines_[line_range_.first - 1];
  std::stringstream orig;
  for (auto c : srcline) {
    if (c == '\t')
      orig << "    ";
    else
      orig << c;
  }
  result.emplace_back(orig.str());

  std::stringstream select;
  for (unsigned int x = 0; x < srcline.size() && x < column_range_.second - 1;
       x++) {
    char marker = x < column_range_.first - 1 ? ' ' : '~';
    if (srcline[x] == '\t') {
      select << std::string(4, marker);
    } else {
      select << marker;
    }
  }
  result.emplace_back(select.str());

  return result;
}

} // namespace bpftrace::ast
