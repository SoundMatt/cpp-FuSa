#include "hooks.hpp"
#include <filesystem>
#include <fstream>
#include <string>

namespace fs = std::filesystem;

namespace cpfusa::hooks {

namespace {

constexpr std::string_view HookScript =
R"(#!/bin/sh
# cpp-FuSa pre-commit hook — installed by: cpfusa hooks install
set -e
if command -v cpfusa >/dev/null 2>&1; then
  cpfusa check --strict
else
  echo "cpfusa: not found in PATH; skipping safety check" >&2
fi
)";

constexpr std::string_view HookMarker = "cpp-FuSa pre-commit hook";

} // namespace

std::string show() { return std::string(HookScript); }

//fusa:req REQ-HOOKS001 REQ-HOOKS003
Result<std::monostate> install(const fs::path& project_root) {
    auto hooks_dir = project_root / ".git" / "hooks";
    if (!fs::exists(hooks_dir)) {
        return std::string("hooks: .git/hooks not found — is this a git repository?");
    }
    auto hook_path = hooks_dir / "pre-commit";
    // Don't overwrite a non-cpfusa hook.
    if (fs::exists(hook_path)) {
        std::ifstream f(hook_path);
        std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        if (content.find(HookMarker) == std::string::npos) {
            return std::string("hooks: pre-commit hook already exists and was not installed by cpfusa");
        }
    }
    try {
        std::ofstream out(hook_path);
        out << HookScript;
    } catch (const std::exception& e) {
        return std::string("hooks: write hook: ") + e.what();
    }
    // Make executable (POSIX)
#if !defined(_WIN32)
    fs::permissions(hook_path,
        fs::perms::owner_exec | fs::perms::owner_read | fs::perms::owner_write |
        fs::perms::group_read | fs::perms::group_exec,
        fs::perm_options::add);
#endif
    return std::monostate{};
}

//fusa:req REQ-HOOKS002
Result<std::monostate> remove(const fs::path& project_root) {
    auto hook_path = project_root / ".git" / "hooks" / "pre-commit";
    if (!fs::exists(hook_path)) return std::monostate{};
    std::ifstream f(hook_path);
    std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    if (content.find(HookMarker) == std::string::npos) {
        return std::string("hooks: pre-commit hook was not installed by cpfusa — not removing");
    }
    fs::remove(hook_path);
    return std::monostate{};
}

} // namespace cpfusa::hooks
