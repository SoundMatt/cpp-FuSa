#pragma once

#include <string>
#include <string_view>
#include <variant>

namespace cpfusa {

constexpr std::string_view Version      = "0.14.3";
constexpr std::string_view VersionMajor = "0";
constexpr std::string_view VersionMinor = "14";
constexpr std::string_view VersionPatch = "2";
constexpr std::string_view SpecVersion  = "1.10.12";

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
    Severity    severity{Severity::INFO};
    std::string message;
    std::string file;          // project-relative, / separators (§4)
    int         line{0};
    std::string remediation;   // actionable hint (spec key: NOT "fix")
    std::string category;      // lint|safety|security|coverage|requirement|…
    std::string standard_id;   // canonical standard id (§2.4.1)
    std::string clause;
    int         column{0};
    int         end_line{0};    // §4 MAY — end of affected span
    int         end_column{0};  // §4 MAY — end of affected span
    std::string fingerprint;   // sha256:… (§4.2)

    Finding() = default;
    Finding(std::string rid, Severity sev, std::string msg,
            std::string f = {}, int ln = 0, std::string rem = {},
            std::string cat = {})
        : rule_id(std::move(rid)), severity(sev), message(std::move(msg)),
          file(std::move(f)), line(ln), remediation(std::move(rem)),
          category(std::move(cat)) {}
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
