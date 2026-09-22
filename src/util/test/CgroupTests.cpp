// Copyright 2026 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "main/Application.h"
#include "test/Catch2.h"
#include "test/TestUtils.h"
#include "test/test.h"
#include "util/Cgroup.h"
#include "util/MetricsRegistry.h"
#include "util/TmpDir.h"

#include <filesystem>
#include <fstream>
#include <thread>

using namespace stellar;

namespace
{
void
writeFile(std::filesystem::path const& path, std::string const& contents)
{
    std::filesystem::create_directories(path.parent_path());
    std::ofstream out(path);
    out << contents;
}
} // namespace

TEST_CASE("cgroup cpu max parsing", "[cgroup]")
{
    REQUIRE(cgroup::parseCpuMax("800000 100000\n") == 8.0);
    REQUIRE(cgroup::parseCpuMax("150000 100000") == 1.5);
    REQUIRE(!cgroup::parseCpuMax("max 100000\n"));
    REQUIRE(!cgroup::parseCpuMax(""));
    REQUIRE(!cgroup::parseCpuMax("800000"));
    REQUIRE(!cgroup::parseCpuMax("800000 0"));
    REQUIRE(!cgroup::parseCpuMax("-1 100000"));
    REQUIRE(!cgroup::parseCpuMax("8x 100000"));
}

TEST_CASE("cgroup v1 CFS quota parsing", "[cgroup]")
{
    REQUIRE(cgroup::parseCfsQuota("400000\n", "100000\n") == 4.0);
    REQUIRE(!cgroup::parseCfsQuota("-1\n", "100000\n"));
    REQUIRE(!cgroup::parseCfsQuota("", "100000"));
}

TEST_CASE("cgroup v2 path parsing", "[cgroup]")
{
    REQUIRE(cgroup::parseUnifiedCgroupPath("0::/\n") == "/");
    REQUIRE(cgroup::parseUnifiedCgroupPath(
                "12:cpu,cpuacct:/x\n0::/user.slice/app.scope\n") ==
            "/user.slice/app.scope");
    REQUIRE(!cgroup::parseUnifiedCgroupPath("12:cpu,cpuacct:/x\n"));
}

TEST_CASE("cgroup CPU quota resolution", "[cgroup]")
{
    TmpDir tmp("cgroup-test");
    std::filesystem::path root = tmp.getName();
    auto self = root / "proc-self-cgroup";

    SECTION("container: namespaced root cgroup")
    {
        writeFile(self, "0::/\n");
        writeFile(root / "fs" / "cpu.max", "800000 100000\n");
        REQUIRE(cgroup::cpuQuota(root / "fs", self) == 8.0);
    }
    SECTION("most restrictive ancestor wins")
    {
        writeFile(self, "0::/a/b\n");
        writeFile(root / "fs" / "a" / "cpu.max", "200000 100000\n");
        writeFile(root / "fs" / "a" / "b" / "cpu.max", "max 100000\n");
        REQUIRE(cgroup::cpuQuota(root / "fs", self) == 2.0);
    }
    SECTION("unlimited")
    {
        writeFile(self, "0::/a\n");
        writeFile(root / "fs" / "a" / "cpu.max", "max 100000\n");
        REQUIRE(!cgroup::cpuQuota(root / "fs", self));
    }
    SECTION("cgroup v1 fallback")
    {
        writeFile(self, "4:cpu,cpuacct:/\n");
        writeFile(root / "fs" / "cpu,cpuacct" / "cpu.cfs_quota_us", "300000\n");
        writeFile(root / "fs" / "cpu,cpuacct" / "cpu.cfs_period_us",
                  "100000\n");
        REQUIRE(cgroup::cpuQuota(root / "fs", self) == 3.0);
    }
    SECTION("nothing readable")
    {
        REQUIRE(!cgroup::cpuQuota(root / "missing", root / "missing-self"));
    }
}

TEST_CASE("cgroup cpu stat parsing", "[cgroup]")
{
    auto stat = cgroup::parseCpuStat("usage_usec 1000\nuser_usec 600\n"
                                     "system_usec 400\nnr_periods 50\n"
                                     "nr_throttled 17\nthrottled_usec 780663\n"
                                     "nr_bursts 0\nburst_usec 0\n");
    REQUIRE(stat);
    REQUIRE(stat->usageUsec == 1000);
    REQUIRE(stat->nrPeriods == 50);
    REQUIRE(stat->nrThrottled == 17);
    REQUIRE(stat->throttledUsec == 780663);

    // No bandwidth limit: throttling fields absent.
    auto unlimited = cgroup::parseCpuStat("usage_usec 5\nuser_usec 5\n");
    REQUIRE(unlimited);
    REQUIRE(unlimited->nrThrottled == 0);

    REQUIRE(!cgroup::parseCpuStat("nr_periods 1\n"));
}

TEST_CASE("cgroup cpu pressure parsing", "[cgroup]")
{
    auto pressure = cgroup::parseCpuPressure(
        "some avg10=12.50 avg60=3.00 avg300=1.00 total=123456\n"
        "full avg10=0.25 avg60=0.00 avg300=0.00 total=789\n");
    REQUIRE(pressure);
    REQUIRE(pressure->someAvg10 == 12.5);
    REQUIRE(pressure->someTotalUsec == 123456);
    REQUIRE(pressure->fullAvg10 == 0.25);
    REQUIRE(pressure->fullTotalUsec == 789);

    REQUIRE(!cgroup::parseCpuPressure(""));
    REQUIRE(!cgroup::parseCpuPressure("some avg10=x total=1\n"));
}

TEST_CASE("cgroup files are read from the process cgroup", "[cgroup]")
{
    TmpDir tmp("cgroup-test");
    std::filesystem::path root = tmp.getName();
    auto self = root / "proc-self-cgroup";
    writeFile(self, "0::/pod/core\n");
    writeFile(root / "fs" / "pod" / "core" / "cpu.stat",
              "usage_usec 42\nnr_periods 3\nnr_throttled 1\n"
              "throttled_usec 9\n");
    writeFile(root / "fs" / "pod" / "core" / "cpu.pressure",
              "some avg10=1.00 avg60=0.00 avg300=0.00 total=5\n");

    auto dir = cgroup::unifiedCgroupDir(root / "fs", self);
    REQUIRE(dir);
    REQUIRE(cgroup::readCpuStat(*dir)->throttledUsec == 9);
    REQUIRE(cgroup::readCpuPressure(*dir)->someTotalUsec == 5);
    REQUIRE(!cgroup::unifiedCgroupDir(root / "missing", self));
}

TEST_CASE("application samples its cgroup CPU accounting", "[cgroup]")
{
    auto dir = cgroup::unifiedCgroupDir();
    if (!dir || !cgroup::readCpuStat(*dir))
    {
        WARN("cgroup v2 CPU accounting unavailable; skipping");
        return;
    }
    VirtualClock clock(VirtualClock::REAL_TIME);
    auto app = createTestApplication(clock, getTestConfig());
    auto& usage =
        app->getMetrics().NewCounter({"process", "cgroup", "cpu-usage-usec"});
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (usage.count() == 0 && std::chrono::steady_clock::now() < deadline)
    {
        clock.crank(false);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    REQUIRE(usage.count() > 0);
}
