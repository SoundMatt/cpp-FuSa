#include "misra.hpp"
#include <chrono>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace cpfusa::misra {

std::string status_str(Status s) {
    switch (s) {
        case Status::Mapped: return "mapped";
        case Status::NA:     return "n/a";
        default:             return "manual";
    }
}

//fusa:req REQ-MISRA001 REQ-MISRA002
std::vector<Rule> mapping_table() {
    return {
        // Required rules mapped to LINT equivalents
        {"A5-2-2",  "Required", "Traditional C-style casts shall not be used",
         Status::Mapped, "LINT007", "LINT007 detects C-style casts"},
        {"A5-2-4",  "Required", "reinterpret_cast shall not be used",
         Status::Mapped, "LINT003", "LINT003 requires fusa:unsafe annotation on reinterpret_cast"},
        {"A6-6-1",  "Required", "goto statements shall not be used",
         Status::Mapped, "LINT002", "LINT002 detects goto statements"},
        {"A15-4-2", "Required", "noexcept shall be used for functions that do not throw",
         Status::Mapped, "LINT010", "LINT010 checks exception specifications"},
        {"A15-5-3", "Required", "The std::terminate() function shall not be called",
         Status::Mapped, "LINT004", "LINT004 detects abort/exit without safe-state"},
        {"A18-5-2", "Required", "Non-placement new and delete shall not be used",
         Status::Mapped, "LINT001", "LINT001 detects raw new/delete"},
        // Advisory rules mapped or NA
        {"A2-13-1", "Advisory", "Only those escape sequences defined in ISO/IEC 14882:2014 shall be used",
         Status::Mapped, "LINT006", "LINT006 checks #define vs constexpr"},
        {"A3-3-2",  "Advisory", "Static and thread-local objects shall be constant-initialized",
         Status::Mapped, "LINT005", "LINT005 detects unannotated global mutable variables"},
        {"A4-5-1",  "Advisory", "Expressions with type enum or enum class shall not be used as operands",
         Status::Manual, "", "No automated check — code review required"},
        {"A7-1-2",  "Advisory", "constexpr specifier shall be used when possible",
         Status::Manual, "", "No automated check — code review required"},
        {"A8-4-7",  "Advisory", "in parameters for not cheap to copy types shall be passed by reference",
         Status::Manual, "", "No automated check — code review required"},
        {"A12-0-2", "Advisory", "Bitwise operations and operations that assume data representation shall not be performed on objects",
         Status::Mapped, "ANAL005", "ANAL005 detects unsafe memcpy on class types"},
        {"M0-1-1",  "Required", "A project shall not contain unreachable code",
         Status::Manual, "", "Covered by clang static analysis"},
        {"M6-4-1",  "Required", "An if statement shall always use braces",
         Status::Manual, "", "No automated check — style enforcer required"},
        {"M6-6-1",  "Required", "Any label referenced by a goto statement shall be declared in the same block",
         Status::Mapped, "LINT002", "LINT002 prohibits goto entirely"},
        {"M7-3-4",  "Required", "using-directives shall not be used",
         Status::Manual, "", "No automated check — code review required"},
        {"M8-4-1",  "Required", "Functions shall not be defined using the ellipsis notation",
         Status::Manual, "", "No automated check — code review required"},
        {"M15-0-3", "Required", "Control shall not be transferred out of a finally block",
         Status::NA,     "", "Not applicable — C++ does not have finally blocks"},
        {"M16-0-1", "Required", "#include directives in a file shall only be preceded by preprocessor directives",
         Status::Manual, "", "No automated check"},
        {"M17-0-5", "Required", "The setjmp macro and longjmp function shall not be used",
         Status::NA,     "", "Enforced by LINT002 prohibition on unstructured jumps"},
    };
}

//fusa:req REQ-MISRA003
Report build_report(bool gaps_only) {
    Report r;
    auto now = std::chrono::system_clock::now();
    auto t   = std::chrono::system_clock::to_time_t(now);
    std::ostringstream ts;
    ts << std::put_time(std::gmtime(&t), "%Y-%m-%dT%H:%M:%SZ");
    r.generated_at = ts.str();

    for (auto& rule : mapping_table()) {
        if (gaps_only && rule.status != Status::Manual) continue;
        r.rules.push_back(rule);
        r.total++;
        switch (rule.status) {
            case Status::Mapped: r.mapped++;   break;
            case Status::NA:     r.na_count++; break;
            default:             r.manual++;   break;
        }
    }
    return r;
}

void write_json(const std::string& path, const Report& r) {
    json j;
    j["generatedAt"] = r.generated_at;
    j["summary"] = {{"total", r.total}, {"mapped", r.mapped},
                    {"na", r.na_count}, {"manual", r.manual}};
    j["rules"] = json::array();
    for (auto& rule : r.rules) {
        j["rules"].push_back({
            {"id", rule.id}, {"category", rule.category},
            {"description", rule.description},
            {"status", status_str(rule.status)},
            {"lintRule", rule.lint_rule},
            {"rationale", rule.rationale}
        });
    }
    std::ofstream f(path);
    f << j.dump(2);
}

void render_text(const Report& r, bool gaps_only) {
    std::cout << "MISRA C++:2023 Mapping Report\n";
    std::cout << std::string(70, '-') << "\n";
    for (auto& rule : r.rules) {
        if (gaps_only && rule.status != Status::Manual) continue;
        const char* m = (rule.status == Status::Mapped) ? "[MAP]"
                      : (rule.status == Status::NA)     ? "[N/A]" : "[MAN]";
        std::cout << m << " " << rule.id << " — " << rule.description << "\n";
        if (!rule.lint_rule.empty())
            std::cout << "       → " << rule.lint_rule << ": " << rule.rationale << "\n";
        else
            std::cout << "       → " << rule.rationale << "\n";
    }
    std::cout << std::string(70, '-') << "\n";
    std::cout << "Total: " << r.total << "  Mapped: " << r.mapped
              << "  N/A: " << r.na_count << "  Manual: " << r.manual << "\n";
}

} // namespace cpfusa::misra
