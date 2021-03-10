#include "probe_intern.h"

namespace bpftrace {
namespace ast {

ProbeInternKey ProbeInternPool::intern(ProbeInternData data) {
  auto key = next_valid_key_++;
  map_[key] = data;

  return key;
}

const ProbeInternData * ProbeInternPool::get(ProbeInternKey key) const {
  auto data = map_.find(key);

  if (data != map_.end())
    return &data->second;
  else
    return nullptr;
}

} // namespace ast
} // namespace bpftrace
