#include "aot.h"

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <fcntl.h>
#include <fstream>
#include <istream>
#include <memory>
#include <streambuf>
#include <sys/mman.h>
#include <sys/stat.h>

#include <cereal/archives/binary.hpp>
#include <cereal/archives/json.hpp>
#include <cereal/types/string.hpp>
#include <cereal/types/unordered_map.hpp>
#include <cereal/types/vector.hpp>
#include <gelf.h>
#include <libelf.h>

#include "filesystem.h"
#include "log.h"
#include "utils.h"

#define AOT_ELF_SECTION ".btaot"
#define AOT_ELF_SECTION_SZ sizeof(AOT_ELF_SECTION)

static constexpr auto AOT_MAGIC = 0xA07;
static constexpr auto AOT_SHIM_NAME = "bpftrace-aotrt";

// AOT payload will have this header at the beginning. We don't worry about
// versioning the header b/c we enforce that an AOT compiled script may only
// be run with the corresponding runtime shim. We enforce it through the
// `version` field, which is the "Robert Sedgwicks hash" of BPFTRACE_VERSION
// macro defined in cmake.
struct Header
{
  uint16_t magic;      // Header magic (can be useful to detect endianness)
  uint16_t unused;     // For future use
  uint32_t header_len; // Length of this struct
  uint64_t version;    // Hash of version string
  uint64_t rr_off;     // RequiredResources offset from start of file
  uint64_t rr_len;     // RequiredResources length
  uint64_t bc_off;     // Bytecode offset from start of file
  uint64_t bc_len;     // Bytecode length
};

static_assert(sizeof(Header) == 48);
static_assert(sizeof(std::size_t) <= sizeof(uint64_t));

namespace bpftrace {
namespace aot {
namespace {

uint32_t rs_hash(const std::string &str)
{
  unsigned int b = 378551;
  unsigned int a = 63689;
  unsigned int hash = 0;

  for (char c : str)
  {
    hash = hash * a + c;
    a = a * b;
  }

  return hash;
}

void serialize_bytecode(const BpfBytecode &bytecode, std::ostream &out)
{
  cereal::BinaryOutputArchive archive(out);
  archive(bytecode);
}

int load_required_resources(BPFtrace &bpftrace, uint8_t *ptr, size_t len)
{
  try
  {
    bpftrace.resources.load_state(ptr, len);
  }
  catch (const std::exception &ex)
  {
    LOG(ERROR) << "Failed to deserialize metadata: " << ex.what();
    return 1;
  }

  return 0;
}

int load_bytecode(BPFtrace &bpftrace, uint8_t *ptr, size_t len)
{
  try
  {
    Membuf mbuf(ptr, ptr + len);
    std::istream istream(&mbuf);
    cereal::BinaryInputArchive archive(istream);
    archive(bpftrace.bytecode_);
  }
  catch (const std::exception &ex)
  {
    LOG(ERROR) << "Failed to deserialize metadata: " << ex.what();
    return 1;
  }

  return 0;
}

// Locates bpftrace_aotrt binary from $PATH and clones it
int clone_shim(const std::string &out)
{
  std::error_code ec;

  const char *path_env = ::getenv("PATH");
  if (!path_env)
  {
    LOG(ERROR) << "$PATH is empty";
    return 1;
  }

  std::optional<std_filesystem::path> shim;
  auto paths = split_string(path_env, ':', true);
  for (const auto &path : paths)
  {
    auto fpath = std_filesystem::path(path) / AOT_SHIM_NAME;
    if (std_filesystem::exists(fpath, ec))
    {
      shim = fpath;
      break;
    }
  }

  if (!shim)
  {
    LOG(ERROR) << "Failed to locate " << AOT_SHIM_NAME
               << " shim binary. Is it in $PATH?";
    return 1;
  }

  auto copyopts = std_filesystem::copy_options::overwrite_existing;
  if (!std_filesystem::copy_file(*shim, out, copyopts, ec) || ec)
  {
    LOG(ERROR) << "Failed to clone aotrt shim: " << ec;
    return 1;
  }

  return 0;
}

// Generates contents of the .BTAOT ELF section.
// The function will clear the contents of `out`, if any.
int generate_section(std::vector<uint8_t> &out,
                     const RequiredResources &resources,
                     const BpfBytecode &bytecode)
{
  // Serialize RuntimeResources
  std::string serialized_metadata;
  try
  {
    std::ostringstream serialized(std::ios::binary);
    resources.save_state(serialized);
    serialized_metadata = serialized.str();
  }
  catch (const std::exception &ex)
  {
    LOG(ERROR) << "Failed to serialize runtime metadata: " << ex.what();
    return 1;
  }

  // Serialize bytecode
  std::string serialized_bytecode;
  try
  {
    std::ostringstream serialized(std::ios::binary);
    serialize_bytecode(bytecode, serialized);
    serialized_bytecode = serialized.str();
  }
  catch (const std::exception &ex)
  {
    LOG(ERROR) << "Failed to serialize bytecode: " << ex.what();
    return 1;
  }

  // Construct the header
  auto hdr_len = sizeof(Header);
  Header hdr = {
    .magic = AOT_MAGIC,
    .unused = 0,
    .header_len = sizeof(Header),
    .version = rs_hash(BPFTRACE_VERSION),
    .rr_off = hdr_len,
    .rr_len = serialized_metadata.size(),
    .bc_off = hdr_len + serialized_metadata.size(),
    .bc_len = serialized_bytecode.size(),
  };

  // Resize the output buffer appropriately
  out.clear();
  out.resize(sizeof(Header) + hdr.rr_len + hdr.bc_len);
  uint8_t *p = out.data();

  // Write out header
  memcpy(p, &hdr, sizeof(Header));
  p += sizeof(Header);

  // Write out metadata
  memcpy(p, serialized_metadata.data(), hdr.rr_len);
  p += hdr.rr_len;

  // Write out bytecode
  memcpy(p, serialized_bytecode.data(), hdr.bc_len);
  p += hdr.bc_len;

  return 0;
}

// Injects the .BTAOT section into the cloned shim
int inject_section(const std::string &out, std::vector<uint8_t> &section)
{
  std::unique_ptr<char[]> strings;
  size_t secnameoff = 0;
  Elf *elf = nullptr;
  Elf_Data *strdata;
  Elf_Data *secdata;
  Elf64_Shdr *shdr;
  Elf_Scn *strsec;
  Elf_Scn *sec;
  int err = 1;

  int fd = ::open(out.c_str(), O_RDWR);
  if (fd < 0)
  {
    LOG(ERROR) << "Failed to open " << out << ": " << std::strerror(errno);
    goto out;
  }

  // Initialize libelf
  if (::elf_version(EV_CURRENT) == EV_NONE)
  {
    LOG(ERROR) << "Failed to initialize libelf: " << ::elf_errmsg(-1);
    goto out;
  }

  // Open elf for modification
  elf = ::elf_begin(fd, ELF_C_RDWR, nullptr);
  if (!elf)
  {
    LOG(ERROR) << "Failed to elf_begin(): " << ::elf_errmsg(-1);
    goto out;
  }

  // Get the string section index
  size_t shstrndx;
  if (::elf_getshdrstrndx(elf, &shstrndx) != 0)
  {
    LOG(ERROR) << "Failed to elf_getshdrstrndx() strsec: " << ::elf_errmsg(-1);
    goto out;
  }

  // Get the string section
  strsec = ::elf_getscn(elf, shstrndx);
  if (!strsec)
  {
    LOG(ERROR) << "Failed to elf_getscn() strsec: " << ::elf_errmsg(-1);
    goto out;
  }

  // Get string section data
  strdata = ::elf_getdata(strsec, nullptr);
  if (!strdata)
  {
    LOG(ERROR) << "Failed to elf_getdata() strsec: " << ::elf_errmsg(-1);
    goto out;
  }

  // Clone string table and add 1 more to end
  secnameoff = strdata->d_size;
  strings = std::make_unique<char[]>(strdata->d_size + AOT_ELF_SECTION_SZ);
  memcpy(strings.get(), strdata->d_buf, strdata->d_size);
  memcpy(strings.get() + strdata->d_size, AOT_ELF_SECTION, AOT_ELF_SECTION_SZ);

  // Update the string table with new data
  strdata->d_buf = strings.get();
  strdata->d_size += AOT_ELF_SECTION_SZ;
  ::elf_flagdata(strdata, ELF_C_SET, ELF_F_DIRTY);

  // Update string table size in SHT
  shdr = ::elf64_getshdr(strsec);
  if (!shdr)
  {
    LOG(ERROR) << "Failed to elf64_getshdr() strsec: " << ::elf_errmsg(-1);
    goto out;
  }
  shdr->sh_size = strdata->d_size;

  // Create new section
  sec = ::elf_newscn(elf);
  if (!sec)
  {
    LOG(ERROR) << "Failed to elf_newscn(): " << ::elf_errmsg(-1);
    goto out;
  }

  // Add section data to our new section
  secdata = ::elf_newdata(sec);
  if (!secdata)
  {
    LOG(ERROR) << "Failed to elf_newdata(): " << ::elf_errmsg(-1);
    goto out;
  }

  secdata->d_buf = section.data();
  secdata->d_size = section.size();
  secdata->d_type = ELF_T_BYTE;
  secdata->d_version = EV_CURRENT;
  secdata->d_align = 1;
  secdata->d_off = 0;
  ::elf_flagdata(secdata, ELF_C_SET, ELF_F_DIRTY);

  // Get section header for new section
  shdr = ::elf64_getshdr(sec);
  if (!shdr)
  {
    LOG(ERROR) << "Failed to elf64_getshdr() new section: " << ::elf_errmsg(-1);
    goto out;
  }

  // Update new section's header
  shdr->sh_type = SHT_PROGBITS;
  shdr->sh_name = secnameoff;
  shdr->sh_entsize = 0;
  shdr->sh_flags = 0;
  shdr->sh_size = secdata->d_size;

  if (::elf_update(elf, ELF_C_NULL) < 0)
  {
    LOG(ERROR) << "elf_update() (layout) failed: " << elf_errmsg(-1);
    goto out;
  }
  if (::elf_update(elf, ELF_C_WRITE) < 0)
  {
    LOG(ERROR) << "Failed to elf_update() (write): " << elf_errmsg(-1);
    goto out;
  }

  err = 0;
out:
  if (elf)
    ::elf_end(elf);
  if (fd >= 0)
    ::close(fd);
  return err;
}

} // namespace

int generate(const RequiredResources &resources,
             const BpfBytecode &bytecode,
             const std::string &out)
{
  std::vector<uint8_t> section;
  int err;

  err = generate_section(section, resources, bytecode);
  if (err)
    return err;

  err = clone_shim(out);
  if (err)
    return err;

  err = inject_section(out, section);
  if (err)
  {
    std::error_code ec;
    if (!std_filesystem::remove(out, ec) || ec)
      LOG(ERROR) << "Failed to remove " << out << ": " << ec;
  }

  return 0;
}

int load(BPFtrace &bpftrace, const std::string &in)
{
  int err = 0;

  int infd = ::open(in.c_str(), O_RDONLY);
  if (infd < 0)
  {
    auto saved_err = errno;
    LOG(ERROR) << "Failed to open: " << in << ": " << std::strerror(saved_err);
    return 1;
  }

  struct stat sb;
  if (fstat(infd, &sb))
  {
    auto saved_err = errno;
    LOG(ERROR) << "Failed to stat: " << in << ": " << std::strerror(saved_err);
    return 1;
  }

  uint8_t *ptr = static_cast<uint8_t *>(
      ::mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, infd, 0));
  if (ptr == MAP_FAILED)
  {
    auto saved_err = errno;
    LOG(ERROR) << "Failed to mmap: " << in << ": " << std::strerror(saved_err);
    return 1;
  }

  // Validate header
  auto hdr = reinterpret_cast<const Header *>(ptr);
  if (hdr->magic != AOT_MAGIC)
  {
    LOG(ERROR) << "Invalid magic in " << in << ": " << hdr->magic;
    err = 1;
    goto out;
  }
  if (hdr->unused != 0)
  {
    LOG(ERROR) << "Unused bytes are used: " << hdr->unused;
    err = 1;
    goto out;
  }
  if (hdr->header_len != sizeof(Header))
  {
    LOG(ERROR) << "Invalid header len: " << hdr->header_len;
    err = 1;
    goto out;
  }
  if (hdr->version != rs_hash(BPFTRACE_VERSION))
  {
    LOG(ERROR) << "Build hash mismatch! "
               << "Did you build with a different bpftrace version?";
    err = 1;
    goto out;
  }
  if ((hdr->rr_off + hdr->rr_len) > static_cast<uint64_t>(sb.st_size) ||
      (hdr->bc_off + hdr->bc_len) > static_cast<uint64_t>(sb.st_size))
  {
    LOG(ERROR) << "Corrupted AOT bpftrace file: incomplete payload";
    err = 1;
    goto out;
  }

  // Load payloads
  err = load_required_resources(bpftrace, ptr + hdr->rr_off, hdr->rr_len);
  if (err)
    goto out;

  err = load_bytecode(bpftrace, ptr + hdr->bc_off, hdr->bc_len);
  if (err)
    goto out;

out:
  if (::munmap(ptr, sb.st_size))
  {
    auto saved_err = errno;
    LOG(ERROR) << "Failed to munmap(): " << in << ": "
               << std::strerror(saved_err);
  }

  return err;
}

} // namespace aot
} // namespace bpftrace
