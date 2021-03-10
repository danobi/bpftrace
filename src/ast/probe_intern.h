#pragma once

#include <cstdint>
#include <limits>
#include <optional>
#include <unordered_map>
#include <string>

namespace bpftrace {
namespace ast {

// Do not create your own keys. Only use the ones provided by
// `ProbeInternPool::intern(..)`.
using ProbeInternKey = uint64_t;

struct ProbeInternData {
  // Section name in llvm ORC
  std::string section_name;
};

class ProbeInternPool
{
public:
  // Intern probe data and return a key
  ProbeInternKey intern(ProbeInternData data);

  // Get interned probe data
  //
  // Returns non-null if found, else null
  const ProbeInternData * get(ProbeInternKey key) const;

private:
  constexpr ProbeInternKey first_key() const {
    return std::numeric_limits<ProbeInternKey>::max() / 2;
  }

  // Start the keys at a non-obvious number (ie not 0 or max)
  ProbeInternKey next_valid_key_{first_key()};
  std::unordered_map<ProbeInternKey, ProbeInternData> map_;
};

} // namespace ast
} // namespace bpftrace
