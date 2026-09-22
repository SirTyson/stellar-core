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

std::optional<CpuStat>
parseCpuStat(std::string const& contents)
{
    std::istringstream in(contents);
    std::string key;
    uint64_t value;
    CpuStat stat;
    bool haveUsage = false;
    while (in >> key >> value)
    {
        if (key == "usage_usec")
        {
            stat.usageUsec = value;
            haveUsage = true;
        }
        else if (key == "nr_periods")
        {
            stat.nrPeriods = value;
        }
        else if (key == "nr_throttled")
        {
            stat.nrThrottled = value;
        }
        else if (key == "throttled_usec")
        {
            stat.throttledUsec = value;
        }
    }
    if (!haveUsage)
    {
        return std::nullopt;
    }
    return stat;
}

std::optional<CpuPressure>
parseCpuPressure(std::string const& contents)
{
    // some avg10=0.00 avg60=0.00 avg300=0.00 total=0
    // full avg10=0.00 avg60=0.00 avg300=0.00 total=0
    std::istringstream in(contents);
    std::string line;
    CpuPressure pressure;
    bool haveSome = false;
    while (std::getline(in, line))
    {
        std::istringstream fields(line);
        std::string kind;
        fields >> kind;
        if (kind != "some" && kind != "full")
        {
            continue;
        }
        std::optional<double> avg10;
        std::optional<uint64_t> total;
        std::string field;
        while (fields >> field)
        {
            auto eq = field.find('=');
            if (eq == std::string::npos)
            {
                continue;
            }
            auto name = field.substr(0, eq);
            auto value = field.substr(eq + 1);
            try
            {
                if (name == "avg10")
                {
                    avg10 = std::stod(value);
                }
                else if (name == "total")
                {
                    total = std::stoull(value);
                }
            }
            catch (std::exception const&)
            {
                return std::nullopt;
            }
        }
        if (!avg10 || !total)
        {
            return std::nullopt;
        }
        if (kind == "some")
        {
            pressure.someAvg10 = *avg10;
            pressure.someTotalUsec = *total;
            haveSome = true;
        }
        else
        {
            pressure.fullAvg10 = *avg10;
            pressure.fullTotalUsec = *total;
        }
    }
    if (!haveSome)
    {
        return std::nullopt;
    }
    return pressure;
}

std::optional<std::filesystem::path>
unifiedCgroupDir(std::filesystem::path const& cgroupRoot,
                 std::filesystem::path const& procSelfCgroup)
{
    auto self = readFile(procSelfCgroup);
    if (!self)
    {
        return std::nullopt;
    }
    auto path = parseUnifiedCgroupPath(*self);
    if (!path)
    {
        return std::nullopt;
    }
    auto const rel = std::filesystem::path(*path).relative_path();
    auto dir = rel.empty() ? cgroupRoot : cgroupRoot / rel;
    std::error_code ec;
    if (!std::filesystem::is_directory(dir, ec))
    {
        return std::nullopt;
    }
    return dir;
}

std::optional<CpuStat>
readCpuStat(std::filesystem::path const& cgroupDir)
{
    auto contents = readFile(cgroupDir / "cpu.stat");
    return contents ? parseCpuStat(*contents) : std::nullopt;
}

std::optional<CpuPressure>
readCpuPressure(std::filesystem::path const& cgroupDir)
{
    auto contents = readFile(cgroupDir / "cpu.pressure");
    return contents ? parseCpuPressure(*contents) : std::nullopt;
}

} // namespace cgroup
} // namespace stellar
