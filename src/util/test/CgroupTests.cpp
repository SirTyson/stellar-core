// Copyright 2026 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "test/Catch2.h"
#include "util/Cgroup.h"
#include "util/TmpDir.h"

#include <filesystem>
#include <fstream>

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
