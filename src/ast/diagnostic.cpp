#include "diagnostic.h"

#include "log.h"

namespace bpftrace::ast {

void Diagnostics::emit(std::ostream& out) const
{
  // Emit all errors first, following by all warnings.
  emit(out, Severity::Error);
  emit(out, Severity::Warning);
}

void Diagnostics::emit(std::ostream& out, Severity s) const
{
  foreach(s, [this, s, &out](const Diagnostic& d) { emit(out, s, d); });
}

void Diagnostics::emit(std::ostream& out, Severity s, const Diagnostic& d) const
{
  // It is both useless and causes infinite recursion to construct context if
  // emitting non-context diagnostics.
  std::ostringstream context;
  if (s != Severity::Context) {
    foreach(Severity::Context, [this, &d, &context](const Diagnostic& ctxd) {
      if (!ctxd.loc().contains(d.loc()))
        return;

      emit(context, Severity::Context, ctxd);
    });
  }

  const auto& loc = d.loc();
  switch (s) {
    case Severity::Context:
      LOG(HINT, loc.source_location(), loc.source_context(), out) << d.msg();
      break;
    case Severity::Warning:
      LOG(WARNING, loc.source_location(), loc.source_context(), out) << d.msg();
      if (auto msg = d.hint(); !msg.empty()) {
        LOG(HINT, out) << msg;
      }
      out << context.str();
      break;
    case Severity::Error:
      LOG(ERROR, loc.source_location(), loc.source_context(), out) << d.msg();
      if (auto msg = d.hint(); !msg.empty()) {
        LOG(HINT, out) << msg;
      }
      out << context.str();
      break;
  }
}

} // namespace bpftrace::ast
