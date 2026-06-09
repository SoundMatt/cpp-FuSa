#pragma once

#include <string>
#include <string_view>
#include <variant>
#include <vector>
#include <optional>
#include <functional>

namespace cpfusa {

constexpr std::string_view Version      = "0.5.0";
constexpr std::string_view VersionMajor = "0";
constexpr std::string_view VersionMinor = "5";
constexpr std::string_view VersionPatch = "0";

enum class Severity { INFO, WARNING, ERROR };

[[nodiscard]] inline std::string_view to_string(Severity s) {
    switch (s) {
        case Severity::INFO:    return "INFO";
        case Severity::WARNING: return "WARNING";
        case Severity::ERROR:   return "ERROR";
    }
    return "UNKNOWN";
}

struct Finding {
    std::string rule_id;
    Severity    severity;
    std::string message;
    std::string file;
    int         line{0};
    std::string fix;
};

// Lightweight result type — avoids exceptions in safety-critical paths.
template <typename T>
using Result = std::variant<T, std::string>;

template <typename T>
[[nodiscard]] bool is_ok(const Result<T>& r) {
    return std::holds_alternative<T>(r);
}
template <typename T>
[[nodiscard]] const T& value_of(const Result<T>& r) {
    return std::get<T>(r);
}
template <typename T>
[[nodiscard]] const std::string& error_of(const Result<T>& r) {
    return std::get<std::string>(r);
}

// Sentinel error strings (never localised so comparisons are stable).
inline constexpr std::string_view ErrNoConfig       = "ENOCONFIG";
inline constexpr std::string_view ErrNoRequirements = "ENOREQS";
inline constexpr std::string_view ErrRuleNotFound   = "ENORULE";
inline constexpr std::string_view ErrIO             = "EIO";

} // namespace cpfusa
