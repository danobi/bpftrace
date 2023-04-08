#pragma once

#include <regex>
#include <sstream>

#include "ast/ast.h"
#include "printf_format_types.h"
#include "types.h"

namespace bpftrace {

static const std::string generate_pattern_string()
{
  std::string pattern = "%-?[0-9]*(\\.[0-9]+)?(";
  for (const auto& e : printf_format_types)
  {
    pattern += e.first + "|";
  }
  pattern.pop_back(); // for the last "|"
  pattern += ")";
  return pattern;
}

const std::regex format_specifier_re(generate_pattern_string());

struct Field;

class IPrintable
{
public:
  virtual ~IPrintable() { };
  virtual int print(char* buf, size_t size, const char* fmt) = 0;
};

class PrintableString : public virtual IPrintable
{
public:
  PrintableString(std::string value, size_t read = 0);
  int print(char* buf, size_t size, const char* fmt) override;

private:
  std::string value_;
};

class PrintableBuffer : public virtual IPrintable
{
public:
  PrintableBuffer(char* buffer, size_t size)
      : value_(std::vector<char>(buffer, buffer + size))
  {
  }
  int print(char* buf, size_t size, const char* fmt) override;
  void keep_ascii(bool value);
  void escape_hex(bool value);

private:
  std::vector<char> value_;
  bool keep_ascii_ = true;
  bool escape_hex_ = true;
};

class PrintableInt : public virtual IPrintable
{
public:
  PrintableInt(uint64_t value) : value_(value) { }
  int print(char* buf, size_t size, const char* fmt) override;

private:
  uint64_t value_;
};

class PrintableSInt : public virtual IPrintable
{
public:
  PrintableSInt(int64_t value) : value_(value)
  {
  }
  int print(char* buf, size_t size, const char* fmt) override;

private:
  int64_t value_;
};

} // namespace bpftrace
