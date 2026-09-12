// Copyright 2026 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "test/Catch2.h"
#include "util/BatchExecutor.h"

#include <atomic>
#include <chrono>
#include <memory>
#include <stdexcept>

using namespace stellar;

namespace
{
template <typename T>
std::vector<std::function<T()>>
makeTasks(int n, std::function<T(int)> const& body)
{
    std::vector<std::function<T()>> tasks;
    tasks.reserve(n);
    for (int i = 0; i < n; ++i)
    {
        tasks.emplace_back([body, i]() { return body(i); });
    }
    return tasks;
}
}

TEST_CASE("BatchExecutor basic tests", "[batchexecutor]")
{
    BatchExecutor exec;
    int const batchSize = 7;
    SECTION("empty batch is a no-op")
    {
        auto results = exec.executeBatch<int>({});
        REQUIRE(results.empty());
    }

    SECTION("results are in task order")
    {
        auto results = exec.executeBatch(
            makeTasks<int>(batchSize, [](int i) { return i * i; }));
        REQUIRE(results.size() == batchSize);
        for (int i = 0; i < batchSize; ++i)
        {
            REQUIRE(results[i] == i * i);
        }
    }

    SECTION("tasks run exactly once")
    {
        std::vector<std::atomic<int>> counts(batchSize);
        for (auto& c : counts)
        {
            c.store(0);
        }
        auto tasks = makeTasks<int>(
            batchSize, [&counts](int i) { return counts[i].fetch_add(1); });
        auto results = exec.executeBatch(std::move(tasks));
        for (int i = 0; i < batchSize; ++i)
        {
            REQUIRE(counts[i].load() == 1);
        }
    }

    SECTION("tasks run concurrently")
    {
        std::atomic<int> arrived{0};
        std::atomic<bool> anyTimedOut{false};
        auto tasks = makeTasks<int>(batchSize, [&](int i) -> int {
            arrived.fetch_add(1);
            auto deadline =
                std::chrono::steady_clock::now() + std::chrono::seconds(10);
            while (arrived.load() < batchSize)
            {
                if (std::chrono::steady_clock::now() > deadline)
                {
                    anyTimedOut.store(true);
                    break;
                }
            }
            return i;
        });
        auto results = exec.executeBatch(std::move(tasks));
        REQUIRE_FALSE(anyTimedOut.load());
        REQUIRE(arrived.load() == batchSize);
    }

    SECTION("task exceptions are rethrown after all finish")
    {
        std::atomic<int> ran{0};
        auto tasks = makeTasks<int>(batchSize, [&](int i) -> int {
            ran.fetch_add(1);
            if (i == 2)
            {
                throw std::logic_error("error");
            }
            return i;
        });
        REQUIRE_THROWS_AS(exec.executeBatch(std::move(tasks)),
                          std::logic_error);
        REQUIRE(ran.load() == batchSize);

        // Executor is still usable after a batch throws.
        auto results = exec.executeBatch(
            makeTasks<int>(batchSize, [](int i) { return i * i; }));
        REQUIRE(results.size() == batchSize);
        for (int i = 0; i < batchSize; ++i)
        {
            REQUIRE(results[i] == i * i);
        }
    }
}

TEST_CASE("BatchExecutor runs many successive batches", "[batchexecutor]")
{
    BatchExecutor exec;
    uniform_int_distribution<> batchDistr(1, 25);
    for (int round = 0; round < 100; ++round)
    {
        int const batchSize = batchDistr(Catch::rng());
        auto results = exec.executeBatch(makeTasks<int>(
            batchSize, [round](int i) { return round * 1000 + i; }));
        for (int i = 0; i < batchSize; ++i)
        {
            REQUIRE(results[i] == round * 1000 + i);
        }
    }
}

TEST_CASE("BatchExecutor ranges cover the input exactly once",
          "[batchexecutor]")
{
    BatchExecutor exec;
    for (size_t count : {0, 1, 2, 7, 8, 9, 31})
    {
        for (size_t tasks : {0, 1, 2, 4, 8})
        {
            CAPTURE(count, tasks);
            std::vector<std::atomic<int>> visits(count);
            std::vector<std::pair<size_t, size_t>> ranges(
                std::max(tasks, size_t{1}));
            std::atomic<bool> valid{true};
            std::atomic<size_t> calls{0};
            auto caller = std::this_thread::get_id();
            exec.executeBatchOverRanges(
                count, tasks, [&](size_t begin, size_t end, size_t index) {
                    ++calls;
                    if (begin >= end || end > count || index >= ranges.size())
                    {
                        valid = false;
                        return;
                    }
                    ranges[index] = {begin, end};
                    if ((tasks <= 1 || count < tasks) &&
                        std::this_thread::get_id() != caller)
                    {
                        valid = false;
                    }
                    for (auto i = begin; i < end; ++i)
                    {
                        ++visits[i];
                    }
                });
            REQUIRE(valid);
            REQUIRE((calls == 0) == (count == 0));
            size_t end = 0;
            for (size_t i = 0; i < calls; ++i)
            {
                REQUIRE(ranges[i].first == end);
                end = ranges[i].second;
            }
            REQUIRE(end == count);
            for (auto const& visited : visits)
            {
                REQUIRE(visited == 1);
            }
        }
    }
}

TEST_CASE("BatchExecutor range exceptions join workers and allow reuse",
          "[batchexecutor]")
{
    BatchExecutor exec;
    std::atomic<int> completed{0};
    REQUIRE_THROWS_AS(exec.executeBatchOverRanges(
                          8, 4,
                          [&](size_t, size_t, size_t index) {
                              if (index == 0)
                              {
                                  throw std::logic_error("range failed");
                              }
                              ++completed;
                          }),
                      std::logic_error);
    REQUIRE(completed == 3);
    exec.executeBatchOverRanges(8, 4,
                                [&](size_t, size_t, size_t) { ++completed; });
    REQUIRE(completed == 7);
}

TEST_CASE("BatchExecutor chunks cover input with private worker state",
          "[batchexecutor]")
{
    BatchExecutor exec;
    for (size_t count : {0, 1, 2, 7, 8, 9, 31, 257})
    {
        for (size_t workers : {0, 1, 2, 4, 8})
        {
            for (size_t chunkSize : {1, 3, 64, 512})
            {
                CAPTURE(count, workers, chunkSize);
                std::vector<std::atomic<int>> visits(count);
                std::vector<std::atomic<int>> active(
                    std::max(workers, size_t{1}));
                std::atomic<bool> valid{true};
                std::atomic<size_t> calls{0};
                auto caller = std::this_thread::get_id();
                exec.executeBatchOverChunks(
                    count, workers, chunkSize,
                    [&](size_t begin, size_t end, size_t worker) {
                        ++calls;
                        if (begin >= end || end > count ||
                            end - begin > chunkSize || worker >= active.size())
                        {
                            valid = false;
                            return;
                        }
                        if (active[worker].fetch_add(1) != 0)
                        {
                            valid = false;
                        }
                        if ((workers <= 1 || count <= chunkSize) &&
                            std::this_thread::get_id() != caller)
                        {
                            valid = false;
                        }
                        for (auto i = begin; i < end; ++i)
                        {
                            ++visits[i];
                        }
                        --active[worker];
                    });
                REQUIRE(valid);
                REQUIRE(calls ==
                        (count == 0 ? 0 : 1 + (count - 1) / chunkSize));
                for (auto const& visited : visits)
                {
                    REQUIRE(visited == 1);
                }
            }
        }
    }
}

TEST_CASE("BatchExecutor keeps processing chunks while one worker is blocked",
          "[batchexecutor]")
{
    BatchExecutor exec;
    std::mutex mutex;
    std::condition_variable condition;
    size_t completed = 0;
    bool finishedWhileBlocked = false;
    exec.executeBatchOverChunks(65, 2, 1, [&](size_t begin, size_t, size_t) {
        std::unique_lock<std::mutex> lock(mutex);
        if (begin == 0)
        {
            // A fixed partition cannot finish all
            // the other items while this one waits.
            finishedWhileBlocked =
                condition.wait_for(lock, std::chrono::seconds(10),
                                   [&] { return completed == 64; });
        }
        else
        {
            ++completed;
            condition.notify_one();
        }
    });
    REQUIRE(finishedWhileBlocked);
    REQUIRE(completed == 64);
}

TEST_CASE("BatchExecutor chunk exceptions join workers and allow reuse",
          "[batchexecutor]")
{
    BatchExecutor exec;
    std::atomic<int> completed{0};
    REQUIRE_THROWS_AS(exec.executeBatchOverChunks(
                          32, 2, 1,
                          [&](size_t begin, size_t, size_t) {
                              if (begin == 0)
                              {
                                  throw std::logic_error("chunk failed");
                              }
                              ++completed;
                          }),
                      std::logic_error);
    REQUIRE(completed == 31);
    exec.executeBatchOverChunks(32, 2, 1,
                                [&](size_t, size_t, size_t) { ++completed; });
    REQUIRE(completed == 63);
}
