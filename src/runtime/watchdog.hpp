#pragma once

// fusa:req REQ-RT001 RAII watchdog timer for safety-critical loops
#include <functional>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <chrono>
#include <stdexcept>

namespace cpfusa::runtime {

// RAII watchdog that calls a handler if kick() is not called within timeout.
// Destructor cancels the watchdog — no explicit stop() needed.
//
// Usage:
//   Watchdog wd(std::chrono::milliseconds{100}, [] { safe_state_handler(); });
//   while (running) {
//       wd.kick();
//       process();
//   }
//fusa:req REQ-RT001 REQ-RT004
class Watchdog {
public:
    using Handler  = std::function<void()>;
    using Duration = std::chrono::milliseconds;

    Watchdog(Duration timeout, Handler on_expire)
        : timeout_(timeout), on_expire_(std::move(on_expire)), alive_(true) {
        if (timeout_.count() <= 0)
            throw std::invalid_argument("Watchdog timeout must be positive");
        thread_ = std::thread([this] { monitor(); });
    }

    // Resets the watchdog timer — must be called within timeout_.
    void kick() noexcept {
        {
            std::unique_lock<std::mutex> lk(mu_);
            kicked_ = true;
        }
        cv_.notify_one();
    }

    ~Watchdog() {
        {
            std::unique_lock<std::mutex> lk(mu_);
            alive_ = false;
        }
        cv_.notify_one();
        if (thread_.joinable()) thread_.join();
    }

    // Non-copyable, non-movable — resource owns a thread.
    Watchdog(const Watchdog&)            = delete;
    Watchdog& operator=(const Watchdog&) = delete;
    Watchdog(Watchdog&&)                 = delete;
    Watchdog& operator=(Watchdog&&)      = delete;

private:
    void monitor() {
        std::unique_lock<std::mutex> lk(mu_);
        while (alive_) {
            kicked_ = false;
            bool expired = !cv_.wait_for(lk, timeout_, [this] {
                return kicked_ || !alive_;
            });
            if (expired && alive_) {
                on_expire_();
            }
        }
    }

    Duration               timeout_;
    Handler                on_expire_;
    std::atomic<bool>      alive_;
    bool                   kicked_{false};
    std::mutex             mu_;
    std::condition_variable cv_;
    std::thread            thread_;
};

} // namespace cpfusa::runtime
