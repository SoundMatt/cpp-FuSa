#pragma once

// fusa:req REQ-RT002 Safe-state transition RAII guard
#include <functional>
#include <atomic>

namespace cpfusa::runtime {

// Scope guard that triggers a safe-state handler on destruction unless
// commit() is called, indicating the operation completed safely.
//
// Usage:
//   SafeStateGuard guard([] { engage_safe_state(); });
//   do_critical_work();
//   guard.commit(); // disarms the guard — no safe-state on normal exit
class SafeStateGuard {
public:
    using Handler = std::function<void()>;

    explicit SafeStateGuard(Handler on_fault) noexcept
        : on_fault_(std::move(on_fault)), armed_(true) {}

    // Disarm — safe path taken, no safe-state needed.
    void commit() noexcept { armed_ = false; }

    ~SafeStateGuard() {
        if (armed_ && on_fault_) {
            // fusa:safe-state intentional — fault path detected
            on_fault_();
        }
    }

    SafeStateGuard(const SafeStateGuard&)            = delete;
    SafeStateGuard& operator=(const SafeStateGuard&) = delete;
    SafeStateGuard(SafeStateGuard&&)                 = delete;
    SafeStateGuard& operator=(SafeStateGuard&&)      = delete;

private:
    Handler            on_fault_;
    bool               armed_;
};

// Atomic safe-state flag — safe to read from ISRs or other threads.
class SafeStateFlag {
public:
    void set() noexcept   { flag_.store(true, std::memory_order_release); }
    void clear() noexcept { flag_.store(false, std::memory_order_release); }
    [[nodiscard]] bool is_set() const noexcept {
        return flag_.load(std::memory_order_acquire);
    }

private:
    std::atomic<bool> flag_{false};
};

} // namespace cpfusa::runtime
