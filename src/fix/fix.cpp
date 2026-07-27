#include "fix.hpp"
#include <iostream>
#include <algorithm>

namespace cpfusa::fix {

//fusa:req REQ-FIX002
std::vector<FixEntry> catalog() {
    return {
        {
            "LINT001", "Raw new/delete",
            "Replace raw heap allocation with smart pointers (MISRA A18-5-2).",
            "int* p = new int(42);",
            "auto p = std::make_unique<int>(42);",
            "MISRA C++:2023 A18-5-2 / AUTOSAR A18-5-2"
        },
        {
            "LINT002", "goto statement", // fusa:suppress LINT002
            "Refactor control flow to eliminate goto (MISRA A6-6-1).", // fusa:suppress LINT002
            "if (err) goto cleanup;", // fusa:suppress LINT002
            "if (err) { cleanup(); return; }",
            "MISRA C++:2023 A6-6-1"
        },
        {
            "LINT003", "reinterpret_cast", // fusa:suppress LINT003
            "Add a fusa:unsafe justification or replace with static_cast (MISRA A5-2-4).", // fusa:suppress LINT003
            "auto p = reinterpret_cast<uint8_t*>(ptr);", // fusa:suppress LINT003
            "// fusa:unsafe hardware register access\nauto p = reinterpret_cast<uint8_t*>(ptr);", // fusa:suppress LINT003
            "MISRA C++:2023 A5-2-4"
        },
        {
            "LINT004", "abort/exit without safe state",
            "Transition to safe state before calling abort/exit (MISRA A15-5-3).",
            "std::abort();",
            "// fusa:safe-state\nsafe_state_handler();\nstd::abort();",
            "MISRA C++:2023 A15-5-3"
        },
        {
            "LINT005", "Global mutable variable",
            "Annotate or make const (AUTOSAR A3-3-2).",
            "int global_counter = 0;",
            "// fusa:shared mutex protected\nint global_counter = 0;",
            "AUTOSAR A3-3-2"
        },
        {
            "LINT006", "#define constant",
            "Replace macro constant with constexpr (MISRA A2-13-1).",
            "#define MAX_BUF 256",
            "constexpr int MAX_BUF = 256;",
            "MISRA C++:2023 A2-13-1"
        },
        {
            "LINT007", "C-style cast",
            "Replace with named cast (MISRA A5-2-2).",
            "auto x = (int)value;",
            "auto x = static_cast<int>(value);",
            "MISRA C++:2023 A5-2-2"
        },
        {
            "LINT008", "Recursive function",
            "Add depth-bound guard annotation (JSF++ 119).",
            "void process(Node* n) { process(n->next); }",
            "// fusa:recursive max-depth=1000\nvoid process(Node* n, int depth=0) {\n    if (depth > 1000) return;\n    process(n->next, depth+1);\n}",
            "JSF++ Rule 119"
        },
        {
            "LINT009", "printf/scanf",
            "Replace with type-safe I/O.",
            "printf(\"%d\\n\", value);",
            "std::cout << value << '\\n';",
            "MISRA C++:2023 / C++ Core Guidelines"
        },
        {
            "LINT010", "Missing noexcept",
            "Mark non-throwing functions noexcept.",
            "int compute() { return 42; }",
            "int compute() noexcept { return 42; }",
            "C++ Core Guidelines E.12"
        },
        {
            "CYBER001", "Unsafe sprintf",
            "Replace sprintf with snprintf or std::format.",
            "sprintf(buf, \"%s\", input);",
            "snprintf(buf, sizeof(buf), \"%s\", input);",
            "CWE-120 / CERT C++ STR50"
        },
        {
            "FUSA001", "Missing .fusa.json",
            "Initialise the project configuration file.",
            "# (no .fusa.json present)",
            "# Run: cpfusa init",
            "cpp-FuSa FUSA001"
        },
        {
            "FUSA004", "Missing test evidence",
            "Run tests and capture evidence.",
            "# (no .fusa-evidence.json present)",
            "# Run: ctest && cpfusa verify",
            "cpp-FuSa FUSA004"
        },
    };
}

//fusa:req REQ-FIX003
void show(const std::string& rule_id) {
    for (auto& e : catalog()) {
        if (e.rule_id == rule_id) {
            std::cout << "Fix guidance for " << e.rule_id << ": " << e.title << "\n";
            std::cout << std::string(70, '-') << "\n";
            std::cout << e.description << "\n\n";
            std::cout << "Standard: " << e.standard_ref << "\n\n";
            std::cout << "Before:\n  " << e.before << "\n\n";
            std::cout << "After:\n  " << e.after << "\n";
            return;
        }
    }
    std::cout << "No fix guidance available for " << rule_id << "\n";
}

void list_all() {
    std::cout << "Available fix guidance:\n";
    std::cout << std::string(50, '-') << "\n";
    for (auto& e : catalog()) {
        std::cout << "  " << e.rule_id << "  " << e.title << "\n";
    }
}

} // namespace cpfusa::fix
