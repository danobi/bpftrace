#include "log.h"
#include "printf.h"
#include "printf_format_types.h"
#include "struct.h"

namespace bpftrace {
PrintableString::PrintableString(std::string value, size_t read)
    : value_(std::move(value))
{
  LOG(DEBUG) << "value=" << value_ << " value_.size()=" << value_.size() << " read=" << read;
  if (value_.size() >= read)
    value_ += "...";
}

int PrintableString::print(char *buf, size_t size, const char *fmt)
{
  return snprintf(buf, size, fmt, value_.c_str());
}

int PrintableBuffer::print(char *buf, size_t size, const char *fmt)
{
  return snprintf(
      buf,
      size,
      fmt,
      hex_format_buffer(value_.data(), value_.size(), keep_ascii_, escape_hex_)
          .c_str());
}

void PrintableBuffer::keep_ascii(bool value)
{
  keep_ascii_ = value;
}

void PrintableBuffer::escape_hex(bool value)
{
  escape_hex_ = value;
}

int PrintableInt::print(char *buf, size_t size, const char *fmt)
{
  return snprintf(buf, size, fmt, value_);
}

int PrintableSInt::print(char *buf, size_t size, const char *fmt)
{
  return snprintf(buf, size, fmt, value_);
}
} // namespace bpftrace
