#pragma once
// hooks installs/removes a cpfusa pre-commit git hook.
#include "cpfusa/fusa.hpp"
#include <filesystem>
#include <string>

namespace cpfusa::hooks {

enum class Action { INSTALL, REMOVE, SHOW };

// install writes the pre-commit hook script to .git/hooks/pre-commit.
//
//fusa:req REQ-HOOKS001
Result<std::monostate> install(const std::filesystem::path& project_root);

// remove deletes the pre-commit hook if it was installed by cpfusa.
Result<std::monostate> remove(const std::filesystem::path& project_root);

// show returns the hook script content.
std::string show();

} // namespace cpfusa::hooks
