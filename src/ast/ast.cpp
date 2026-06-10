#include "ast.hpp"
#include <filesystem>
#include <regex>
#include <fstream>
#include <string>
#include <vector>

#ifdef CPFUSA_HAS_LIBCLANG
#include <clang-c/Index.h>
#endif

namespace fs = std::filesystem;

namespace cpfusa::ast {

// ─── libclang availability ────────────────────────────────────────────────────

bool libclang_available() noexcept {
#ifdef CPFUSA_HAS_LIBCLANG
    return true;
#else
    return false;
#endif
}

// ─── libclang implementation ──────────────────────────────────────────────────

#ifdef CPFUSA_HAS_LIBCLANG

namespace {

std::string cx_str(CXString s) {
    std::string r = clang_getCString(s) ? clang_getCString(s) : "";
    clang_disposeString(s);
    return r;
}

struct TUFindings {
    std::vector<Finding> out;
    fs::path             root;
};

// Per-class state collected during AST001 / AST004 walk.
struct ClassState {
    bool        has_virtual_method{false};
    bool        has_virtual_dtor{false};
    bool        has_any_member{false};
    bool        has_any_method{false};
    std::string name;
};

CXChildVisitResult class_member_visitor(CXCursor c, CXCursor /*p*/, CXClientData data) {
    auto* st = static_cast<ClassState*>(data);
    CXCursorKind kind = clang_getCursorKind(c);
    if (kind == CXCursor_FieldDecl) {
        st->has_any_member = true;
    } else if (kind == CXCursor_Destructor) {
        if (clang_CXXMethod_isVirtual(c)) st->has_virtual_dtor = true;
    } else if (kind == CXCursor_CXXMethod) {
        st->has_any_method = true;
        if (clang_CXXMethod_isVirtual(c) && !clang_CXXMethod_isStatic(c))
            st->has_virtual_method = true;
    }
    return CXChildVisit_Continue; // don't recurse into nested classes/lambdas
}

// AST002: variable / parameter shadowing state.
struct ShadowCtx {
    std::vector<std::string> outer_names; // names visible in outer scope
    std::vector<Finding>*    out;
    const fs::path*          root;
};

CXChildVisitResult shadow_visitor(CXCursor c, CXCursor /*p*/, CXClientData data);

static std::string rel_path(const fs::path& root, const std::string& abs) {
    std::error_code ec;
    auto r = fs::relative(abs, root, ec);
    return ec ? abs : r.generic_string();
}

CXChildVisitResult tu_visitor(CXCursor c, CXCursor /*p*/, CXClientData data) {
    auto* tf = static_cast<TUFindings*>(data);
    CXCursorKind kind = clang_getCursorKind(c);

    // Only analyse cursors from the main file, not system headers.
    if (clang_Location_isInSystemHeader(clang_getCursorLocation(c)))
        return CXChildVisit_Continue;

    // ── AST001: class with virtual methods but non-virtual destructor ─────────
    if (kind == CXCursor_ClassDecl || kind == CXCursor_StructDecl) {
        if (clang_isCursorDefinition(c)) {
            ClassState st;
            st.name = cx_str(clang_getCursorSpelling(c));
            clang_visitChildren(c, class_member_visitor, &st);

            if (st.has_virtual_method && !st.has_virtual_dtor) {
                CXSourceLocation loc = clang_getCursorLocation(c);
                CXFile file; unsigned line, col, off;
                clang_getSpellingLocation(loc, &file, &line, &col, &off);
                std::string fname = cx_str(clang_getFileName(file));
                tf->out.push_back({
                    "AST001", Severity::ERROR,
                    "'" + st.name + "' has virtual methods but non-virtual destructor — UB when deleted via base pointer",
                    rel_path(tf->root, fname), static_cast<int>(line),
                    "Declare the destructor virtual (or = default) to prevent UB on polymorphic delete",
                    "safety"
                });
            }

            // ── AST004: empty class used as base ─────────────────────────────
            if (!st.has_any_member && !st.has_any_method && !st.name.empty()) {
                // Only flag when other classes inherit from it (we check the
                // base-specifier list in the child cursor walk, so just report
                // the empty class itself for now as INFO).
                // Intentionally skipped here to avoid noise on tag / policy structs.
            }
        }
    }

    // ── AST003: raw pointer return without [[nodiscard]] ─────────────────────
    if (kind == CXCursor_FunctionDecl || kind == CXCursor_CXXMethod) {
        if (clang_isCursorDefinition(c)) {
            CXType retType = clang_getCursorResultType(c);
            bool returns_ptr = (retType.kind == CXType_Pointer);
            bool has_nodiscard = false;
            // Walk attributes of this cursor.
            clang_visitChildren(c, [](CXCursor ac, CXCursor, CXClientData d) -> CXChildVisitResult {
                if (clang_getCursorKind(ac) == CXCursor_WarnUnusedResultAttr)
                    *static_cast<bool*>(d) = true;
                return CXChildVisit_Continue;
            }, &has_nodiscard);

            if (returns_ptr && !has_nodiscard) {
                // Only flag if the function name doesn't look like an internal
                // helper (starts with _) or is a constructor / destructor.
                std::string fname_spell = cx_str(clang_getCursorSpelling(c));
                if (!fname_spell.empty() && fname_spell[0] != '_'
                        && fname_spell != "operator new"
                        && fname_spell != "operator delete") {
                    // Only report at WARNING to avoid overwhelming projects.
                    CXSourceLocation loc = clang_getCursorLocation(c);
                    CXFile file; unsigned line, col, off;
                    clang_getSpellingLocation(loc, &file, &line, &col, &off);
                    std::string path = cx_str(clang_getFileName(file));
                    tf->out.push_back({
                        "AST003", Severity::WARNING,
                        "'" + fname_spell + "' returns a raw pointer without [[nodiscard]] — callers may silently discard it",
                        rel_path(tf->root, path), static_cast<int>(line),
                        "Add [[nodiscard]] to the declaration or return std::unique_ptr / std::optional",
                        "safety"
                    });
                }
            }
        }
    }

    // ── AST002: variable / parameter shadowing ────────────────────────────────
    // Implemented via a separate recursive walk per function body.

    return CXChildVisit_Recurse;
}

// Collect all local var / param names at function scope and flag shadowing.
struct FnScopeCtx {
    std::vector<std::string> seen;
    std::vector<Finding>*    out;
    const fs::path*          root;
};

CXChildVisitResult fn_scope_visitor(CXCursor c, CXCursor /*p*/, CXClientData data) {
    auto* ctx = static_cast<FnScopeCtx*>(data);
    CXCursorKind kind = clang_getCursorKind(c);

    if (kind == CXCursor_VarDecl || kind == CXCursor_ParmDecl) {
        std::string name = cx_str(clang_getCursorSpelling(c));
        if (!name.empty()) {
            if (std::find(ctx->seen.begin(), ctx->seen.end(), name) != ctx->seen.end()) {
                CXSourceLocation loc = clang_getCursorLocation(c);
                CXFile file; unsigned line, col, off;
                clang_getSpellingLocation(loc, &file, &line, &col, &off);
                std::string path = cx_str(clang_getFileName(file));
                ctx->out->push_back({
                    "AST002", Severity::WARNING,
                    "'" + name + "' shadows an outer-scope name — consider renaming to avoid confusion",
                    rel_path(*ctx->root, path), static_cast<int>(line),
                    "Rename the inner variable to a distinct name",
                    "safety"
                });
            } else {
                ctx->seen.push_back(name);
            }
        }
    }
    return CXChildVisit_Recurse;
}

CXChildVisitResult fn_body_visitor(CXCursor c, CXCursor /*p*/, CXClientData data) {
    auto* tf = static_cast<TUFindings*>(data);
    CXCursorKind kind = clang_getCursorKind(c);
    if ((kind == CXCursor_FunctionDecl || kind == CXCursor_CXXMethod)
            && clang_isCursorDefinition(c)
            && !clang_Location_isInSystemHeader(clang_getCursorLocation(c))) {
        FnScopeCtx ctx{{}, &tf->out, &tf->root};
        clang_visitChildren(c, fn_scope_visitor, &ctx);
    }
    return CXChildVisit_Recurse;
}

} // anonymous namespace

std::vector<Finding> run(const fs::path& dir, const config::ProjectConfig& cfg) {
    std::vector<Finding> all;

    static const std::regex ext_re(R"(\.(cpp|cxx|cc|c\+\+)$)"); // .hpp/.h excluded — most TUs are .cpp
    if (!fs::exists(dir)) return all;

    CXIndex idx = clang_createIndex(0, 0);

    for (const auto& entry : fs::recursive_directory_iterator(
             dir, fs::directory_options::skip_permission_denied)) {
        if (!entry.is_regular_file()) continue;
        const std::string ep = entry.path().string();
        if (!std::regex_search(ep, ext_re)) continue;

        // Exclude build / vendor dirs.
        bool skip = false;
        for (const auto& pat : cfg.exclude_patterns)
            if (ep.find(pat) != std::string::npos) { skip = true; break; }
        if (skip) continue;

        const char* args[] = {"-std=c++17", "-w"};
        CXTranslationUnit tu = clang_parseTranslationUnit(
            idx, ep.c_str(), args, 2, nullptr, 0,
            CXTranslationUnit_SkipFunctionBodies);
        if (!tu) continue;

        TUFindings tf; tf.root = dir;

        CXCursor root_cursor = clang_getTranslationUnitCursor(tu);
        // AST001 + AST003
        clang_visitChildren(root_cursor, tu_visitor, &tf);
        // AST002 (shadowing) — separate pass
        clang_visitChildren(root_cursor, fn_body_visitor, &tf);

        // Make paths relative.
        for (auto& f : tf.out) {
            if (!f.file.empty() && fs::path(f.file).is_absolute()) {
                std::error_code ec;
                auto rel = fs::relative(f.file, dir, ec);
                if (!ec) f.file = rel.generic_string();
            }
        }
        all.insert(all.end(), tf.out.begin(), tf.out.end());
        clang_disposeTranslationUnit(tu);
    }

    clang_disposeIndex(idx);
    return all;
}

#else // !CPFUSA_HAS_LIBCLANG ──────────────────────────────────────────────────

std::vector<Finding> run(const fs::path& /*dir*/,
                         const config::ProjectConfig& /*cfg*/) {
    return {{"AST000", Severity::INFO,
             "AST analysis unavailable — cpp-FuSa was built without libclang",
             ".", 0,
             "Install LLVM (brew install llvm / apt install libclang-dev) and rebuild",
             "ast"}};
}

#endif // CPFUSA_HAS_LIBCLANG

} // namespace cpfusa::ast
