// Copyright 2026 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "util/Cgroup.h"

#include <algorithm>
#include <fstream>
#include <sstream>

namespace stellar
{
namespace cgroup
{

namespace
{
std::optional<std::string>
readFile(std::filesystem::path const& path)
{
    std::ifstream in(path);
    if (!in)
    {
        return std::nullopt;
    }
    std::stringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

std::optional<double>
minQuota(std::optional<double> a, std::optional<double> b)
{
    if (!a)
    {
        return b;
    }
    if (!b)
    {
        return a;
    }
    return std::min(*a, *b);
}
} // namespace

std::optional<double>
parseCpuMax(std::string const& contents)
{
    std::istringstream in(contents);
    std::string quota;
    long long period = 0;
    if (!(in >> quota >> period) || period <= 0 || quota == "max")
    {
        return std::nullopt;
    }
    try
    {
        size_t used = 0;
        long long q = std::stoll(quota, &used);
        if (used != quota.size() || q <= 0)
        {
            return std::nullopt;
        }
        return static_cast<double>(q) / static_cast<double>(period);
    }
    catch (std::exception const&)
    {
        return std::nullopt;
    }
}

std::optional<double>
parseCfsQuota(std::string const& quota, std::string const& period)
{
    std::istringstream qin(quota);
    std::istringstream pin(period);
    long long q = 0;
    long long p = 0;
    if (!(qin >> q) || !(pin >> p) || q <= 0 || p <= 0)
    {
        return std::nullopt;
    }
    return static_cast<double>(q) / static_cast<double>(p);
}

std::optional<std::string>
parseUnifiedCgroupPath(std::string const& contents)
{
    std::istringstream in(contents);
    std::string line;
    while (std::getline(in, line))
    {
        if (line.rfind("0::", 0) == 0)
        {
            return line.substr(3);
        }
    }
    return std::nullopt;
}

std::optional<double>
cpuQuota(std::filesystem::path const& cgroupRoot,
         std::filesystem::path const& procSelfCgroup)
{
#ifdef __linux__
    std::optional<double> result;

    // cgroup v2: the effective limit is the most restrictive one on the path
    // from this process's cgroup up to the root. Inside a container with a
    // cgroup namespace the path is "/" and the mount is the container's own
    // cgroup.
    std::string relative = "/";
    if (auto self = readFile(procSelfCgroup))
    {
        if (auto path = parseUnifiedCgroupPath(*self))
        {
            relative = *path;
        }
    }
    auto const rel = std::filesystem::path(relative).relative_path();
    auto dir = rel.empty() ? cgroupRoot : cgroupRoot / rel;
    while (true)
    {
        if (auto contents = readFile(dir / "cpu.max"))
        {
            result = minQuota(result, parseCpuMax(*contents));
        }
        if (dir == cgroupRoot || !dir.has_parent_path() ||
            dir.parent_path() == dir)
        {
            break;
        }
        dir = dir.parent_path();
    }
    if (result)
    {
        return result;
    }

    // cgroup v1 (as seen from inside a container).
    for (auto const& cpuDir : {cgroupRoot / "cpu", cgroupRoot / "cpu,cpuacct"})
    {
        auto quota = readFile(cpuDir / "cpu.cfs_quota_us");
        auto period = readFile(cpuDir / "cpu.cfs_period_us");
        if (quota && period)
        {
            result = minQuota(result, parseCfsQuota(*quota, *period));
        }
    }
    return result;
#else
    (void)cgroupRoot;
    (void)procSelfCgroup;
    return std::nullopt;
#endif
}

} // namespace cgroup
} // namespace stellar
