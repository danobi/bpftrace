#pragma once

#include <functional>
#include <string>
#include <vector>

#include "bpftrace.h"

namespace bpftrace {

struct IterProbeItem
{
  std::string name;
  std::string ctx_type;
  std::vector<std::string> ctx_args;
  std::function<bool(BPFtrace &)> supported;
};

const std::vector<IterProbeItem> ITER_PROBE_LIST = {
  // clang-format off
  {
    .name = "task",
    .ctx_type = "bpf_iter__task",
    .ctx_args = { "struct task_struct * task" },
    .supported = [](BPFtrace &b) {
      return b.btf_.has_data() && b.feature_->has_prog_iter_task();
    }
  },
  {
    .name = "task_file",
    .ctx_type = "bpf_iter__task_file",
    .ctx_args = { "struct task_struct * task", "int fd", "struct file * file" },
    .supported = [](BPFtrace &b) {
      return b.btf_.has_data() && b.feature_->has_prog_iter_task_file();
    }
  },
  {
    .name = "pagecache",
    .ctx_type = "bpf_iter__pagecache",
    .ctx_args = { "struct page * page" },
    .supported = [](BPFtrace &b) {
      return b.btf_.has_data() && b.feature_->has_prog_iter_pagecache();
    }
  }
  // clang-format on
};

} // namespace bpftrace
