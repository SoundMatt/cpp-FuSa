#pragma once

// fusa:req REQ-RT003 Heartbeat monitor for liveness detection
#include <functional>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <chrono>
#include <cstdint>

namespace cpfusa::runtime {

// Periodic heartbeat monitor. Calls on_alive() each period; if beat() is
// not called within the period, calls on_missed() instead.
//
// Usage:
//   Heartbeat hb(std::chrono::seconds{1},
//                [] { log("alive"); },
//                [] { raise_alarm(); });
//   // In task loop:
//   hb.beat();
class Heartbeat {
public:
    using Handler  = std::function<void()>;
    using Duration = std::chrono::milliseconds;

    Heartbeat(Duration period, Handler on_alive, Handler on_missed)
        : period_(period),
          on_alive_(std::move(on_alive)),
          on_missed_(std::move(on_missed)),
          running_(true) {
        thread_ = std::thread([this] { monitor(); });
    }

    void beat() noexcept {
        beat_count_.fetch_add(1, std::memory_order_relaxed);
    }

    [[nodiscard]] uint64_t total_beats() const noexcept {
        return beat_count_.load(std::memory_order_relaxed);
    }

    ~Heartbeat() {
        running_.store(false, std::memory_order_release);
        cv_.notify_one();
        if (thread_.joinable()) thread_.join();
    }

    Heartbeat(const Heartbeat&)            = delete;
    Heartbeat& operator=(const Heartbeat&) = delete;
    Heartbeat(Heartbeat&&)                 = delete;
    Heartbeat& operator=(Heartbeat&&)      = delete;

private:
    void monitor() {
        while (running_.load(std::memory_order_acquire)) {
            auto prev = beat_count_.load(std::memory_order_relaxed);
            std::unique_lock<std::mutex> lk(mu_);
            cv_.wait_for(lk, period_, [this] {
                return !running_.load(std::memory_order_acquire);
            });
            if (!running_.load(std::memory_order_acquire)) break;
            auto now = beat_count_.load(std::memory_order_relaxed);
            if (now > prev) { if (on_alive_)  on_alive_();  }
            else            { if (on_missed_) on_missed_(); }
        }
    }

    Duration               period_;
    Handler                on_alive_;
    Handler                on_missed_;
    std::atomic<bool>      running_;
    std::atomic<uint64_t>  beat_count_{0};
    std::mutex             mu_;
    std::condition_variable cv_;
    std::thread            thread_;
};

} // namespace cpfusa::runtime
