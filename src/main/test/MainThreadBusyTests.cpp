// Copyright 2026 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "main/Application.h"
#include "test/Catch2.h"
#include "test/TestUtils.h"
#include "test/test.h"
#include "util/MetricsRegistry.h"

#include <chrono>
#include <thread>

using namespace stellar;

TEST_CASE("main thread busy time is recorded per task", "[app]")
{
    VirtualClock clock;
    auto app = createTestApplication(clock, getTestConfig());
    auto& metrics = app->getMetrics();
    auto& total = metrics.NewTimer({"app", "main-thread", "busy"});
    auto const totalBefore = total.count();

    int ran = 0;
    for (int i = 0; i < 2; ++i)
    {
        app->postOnMainThread(
            [&]() {
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
                ++ran;
            },
            "Test: Busy Task!", Scheduler::ActionType::NORMAL_ACTION);
    }
    while (ran < 2)
    {
        clock.crank(true);
    }

    REQUIRE(total.count() >= totalBefore + 2);
    // Names become lower-case, dash-separated metric names.
    auto& perTask =
        metrics.NewTimer({"app", "main-thread-busy", "test-busy-task"});
    REQUIRE(perTask.count() == 2);
    REQUIRE(perTask.min() >= 5.0); // milliseconds
}
