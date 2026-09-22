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

// Cumulative CPU accounting of a cgroup v2 (`cpu.stat`).
struct CpuStat
{
    uint64_t usageUsec{0};
    // CFS bandwidth control: enforcement periods elapsed, periods in which
    // the cgroup was throttled, and total time throttled.
    uint64_t nrPeriods{0};
    uint64_t nrThrottled{0};
    uint64_t throttledUsec{0};
};

// Parses `cpu.stat` contents; nullopt if `usage_usec` is missing. Throttling
// fields are 0 when absent (no CPU bandwidth limit).
std::optional<CpuStat> parseCpuStat(std::string const& contents);

// CPU pressure stall information (`cpu.pressure`): the share of time (in
// percent, averaged over 10 s) some / all tasks were stalled waiting for
// CPU, and the cumulative stall time.
struct CpuPressure
{
    double someAvg10{0};
    uint64_t someTotalUsec{0};
    double fullAvg10{0};
    uint64_t fullTotalUsec{0};
};

std::optional<CpuPressure> parseCpuPressure(std::string const& contents);

// This process's cgroup v2 directory, if it has one.
std::optional<std::filesystem::path> unifiedCgroupDir(
    std::filesystem::path const& cgroupRoot = "/sys/fs/cgroup",
    std::filesystem::path const& procSelfCgroup = "/proc/self/cgroup");

std::optional<CpuStat> readCpuStat(std::filesystem::path const& cgroupDir);
std::optional<CpuPressure>
readCpuPressure(std::filesystem::path const& cgroupDir);

} // namespace cgroup
} // namespace stellar
