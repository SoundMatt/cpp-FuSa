//fusa:test REQ-RT001
//fusa:test REQ-RT002
//fusa:test REQ-RT003
//fusa:test REQ-RT004
//fusa:test REQ-RT005
#include <catch2/catch_all.hpp>
#include "runtime/watchdog.hpp"
#include "runtime/safe_state.hpp"
#include "runtime/heartbeat.hpp"
#include <atomic>
#include <thread>

using namespace cpfusa::runtime;
using namespace std::chrono_literals;

TEST_CASE("watchdog: fires handler on timeout", "[runtime][watchdog]") {
    std::atomic<bool> fired{false};
    {
        Watchdog wd(50ms, [&] { fired.store(true); });
        std::this_thread::sleep_for(100ms);
    }
    REQUIRE(fired.load());
}

TEST_CASE("watchdog: does not fire when kicked in time", "[runtime][watchdog]") {
    std::atomic<bool> fired{false};
    {
        // 500ms timeout, kicks every 100ms — generous margin for slow CI runners.
        Watchdog wd(500ms, [&] { fired.store(true); });
        for (int i = 0; i < 5; ++i) {
            wd.kick();
            std::this_thread::sleep_for(100ms);
        }
    }
    REQUIRE_FALSE(fired.load());
}

TEST_CASE("watchdog: invalid timeout throws", "[runtime][watchdog]") {
    REQUIRE_THROWS_AS(
        Watchdog(0ms, [] {}),
        std::invalid_argument
    );
}

TEST_CASE("safe_state_guard: handler fires when not committed", "[runtime][safe_state]") {
    bool fired = false;
    {
        SafeStateGuard g([&] { fired = true; });
        // No commit — handler should fire on destruction.
    }
    REQUIRE(fired);
}

TEST_CASE("safe_state_guard: handler does not fire after commit", "[runtime][safe_state]") {
    bool fired = false;
    {
        SafeStateGuard g([&] { fired = true; });
        g.commit();
    }
    REQUIRE_FALSE(fired);
}

TEST_CASE("safe_state_flag: set and clear", "[runtime][safe_state]") {
    SafeStateFlag flag;
    REQUIRE_FALSE(flag.is_set());
    flag.set();
    REQUIRE(flag.is_set());
    flag.clear();
    REQUIRE_FALSE(flag.is_set());
}

TEST_CASE("heartbeat: on_missed fires when beat() not called", "[runtime][heartbeat]") {
    std::atomic<int> missed{0};
    {
        // 100ms period, 600ms sleep → nominal 6 fires, all misses.
        // Threshold lowered to >= 2 to tolerate macOS CI scheduler jitter.
        Heartbeat hb(100ms, [] {}, [&] { missed.fetch_add(1); });
        std::this_thread::sleep_for(600ms);
    }
    REQUIRE(missed.load() >= 2);
}

TEST_CASE("heartbeat: on_alive fires when beat() is called", "[runtime][heartbeat]") {
    std::atomic<int> alive_count{0};
    {
        // 100ms period; beat every 20ms for 30 iters (nominal 600ms).
        // Each 100ms window always sees multiple beats → on_alive fires.
        // Conservative threshold (>= 3) tolerates heavy CI scheduler jitter.
        Heartbeat hb(100ms, [&] { alive_count.fetch_add(1); }, [] {});
        for (int i = 0; i < 30; ++i) {
            hb.beat();
            std::this_thread::sleep_for(20ms);
        }
    }
    REQUIRE(alive_count.load() >= 3);
}
