#pragma once

// Copyright 2026 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include <filesystem>
#include <optional>
#include <string>

namespace stellar
{
namespace cgroup
{

// Parses the contents of a cgroup v2 `cpu.max` file ("<quota|max> <period>")
// into a number of CPUs (quota / period). Returns nullopt when unlimited
// ("max") or malformed.
std::optional<double> parseCpuMax(std::string const& contents);

// Parses cgroup v1 `cpu.cfs_quota_us` / `cpu.cfs_period_us` contents into a
// number of CPUs. Returns nullopt when unlimited (quota -1) or malformed.
std::optional<double> parseCfsQuota(std::string const& quota,
                                    std::string const& period);

// Parses the cgroup v2 entry ("0::<path>") of /proc/self/cgroup contents.
std::optional<std::string> parseUnifiedCgroupPath(std::string const& contents);

// The CPU bandwidth quota (in CPUs) that applies to this process: the most
// restrictive `cpu.max` of its cgroup v2 hierarchy (its own cgroup and every
// ancestor), falling back to the cgroup v1 CFS quota. Returns nullopt when
// there is none or it cannot be determined (e.g. on non-Linux platforms).
// `cgroupRoot` is the cgroup filesystem mount point; tests can redirect it.
std::optional<double>
cpuQuota(std::filesystem::path const& cgroupRoot = "/sys/fs/cgroup",
         std::filesystem::path const& procSelfCgroup = "/proc/self/cgroup");

} // namespace cgroup
} // namespace stellar
