#include "cyber.hpp"
#include "cpfusa/fusa.hpp"
#include <nlohmann/json.hpp>
#include <filesystem>
#include <fstream>
#include <regex>
#include <sstream>
#include <chrono>
#include <iomanip>
#include <ctime>

namespace fs = std::filesystem;
using json   = nlohmann::json;

namespace cpfusa::cyber {

namespace {

struct Rule {
    std::string id;
    std::string cwe;
    Severity    sev;
    std::regex  re;
    std::string message;
    std::string fix;
};

// Returns ISO-8601 UTC timestamp.
std::string now_iso8601() {
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::ostringstream ss;
    ss << std::put_time(std::gmtime(&t), "%FT%TZ");
    return ss.str();
}

bool is_source(const fs::path& p) {
    static const std::regex ext_re(R"(\.(cpp|cxx|cc|c\+\+|hpp|hxx|h)$)");
    return std::regex_search(p.string(), ext_re);
}

// A rule's own catalogue documentation/messages, and third-party fix/example
// text, inevitably contain the very keyword patterns this scanner is looking
// for — self-scanning cpp-FuSa's own source would otherwise misreport every
// one of those as a genuine finding in its own code. Mirrors lint::suppressed's
// identical, already-precedented mechanism (see .fusa-dispositions.json's
// LINT001 entry for the same rationale) rather than inventing a second
// convention.
bool suppressed(const std::string& line, const std::string& rule_id) {
    return line.find("// fusa:suppress " + rule_id) != std::string::npos
        || line.find("// NOLINT") != std::string::npos;
}

bool is_excluded(const fs::path& p, const config::ProjectConfig& cfg) {
    // generic_string() (always "/"-separated) — excludePatterns are "/"-style
    // gitignore globs (§1.2.1) regardless of platform; p.string() would use
    // "\"-separated native form on Windows and silently never match.
    auto s = p.generic_string();
    for (const auto& pat : cfg.exclude_patterns) {
        if (s.find(pat) != std::string::npos) return true;
    }
    return false;
}

//fusa:req REQ-CYBER001 REQ-CYBER002 REQ-CYBER003 REQ-CYBER004 REQ-CYBER005 REQ-CYBER006 REQ-CYBER007 REQ-CYBER008 REQ-CYBER009 REQ-CYBER010
std::vector<Rule> build_rules() {
    return {
        {
            "CYBER001", "CWE-327", Severity::ERROR,
            std::regex(R"re(\bMD5_Init\b|\bSHA1_Init\b|\b[Mm][Dd]5\b|\bsha1\b|\bSHA1\b|\bMD5\b)re"),
            "Weak cryptographic hash (MD5/SHA-1) detected — use SHA-256 or stronger", // fusa:suppress CYBER001
            "Replace with SHA-256 (e.g. OpenSSL EVP_DigestInit with EVP_sha256())"
        },
        {
            "CYBER002", "CWE-327", Severity::ERROR,
            std::regex(R"re(\bDES_\w+\b|\b3DES\b|\bRC4\b|\bRC2\b|\bBF_\w+\b)re"),
            "Weak symmetric cipher (DES/3DES/RC4) detected — use AES-256-GCM", // fusa:suppress CYBER002
            "Replace with AES-256 in GCM mode"
        },
        {
            "CYBER003", "CWE-330", Severity::ERROR,
            std::regex(R"re(\bsrand\s*\(|\brand\s*\(\))re"),
            "Insecure random number generator (rand/srand) — use a CSPRNG",
            "Use std::random_device or platform CSPRNG (getrandom/BCryptGenRandom)"
        },
        {
            "CYBER004", "CWE-242", Severity::WARNING,
            std::regex(R"re(\breinterpret_cast\s*<)re"), // fusa:suppress LINT003
            "Unsafe reinterpret_cast detected — CWE-242 / MISRA 11.3", // fusa:suppress LINT003
            "Avoid reinterpret_cast; use static_cast with explicit range checks" // fusa:suppress LINT003
        },
        {
            "CYBER005", "CWE-78", Severity::ERROR,
            std::regex(R"re(\bsystem\s*\(|\bpopen\s*\()re"),
            "Command injection risk: system()/popen() call — CWE-78", // fusa:suppress CYBER005
            "Use execv() family with explicit argument arrays instead"
        },
        {
            "CYBER006", "CWE-798", Severity::ERROR,
            std::regex(R"re((?:password|passwd|secret|api_?key|token)\s*=\s*["'][^"']{4,}["'])re", std::regex::icase),
            "Hardcoded credential detected — CWE-798",
            "Load credentials from environment variables or a secrets manager"
        },
        {
            "CYBER007", "CWE-295", Severity::ERROR,
            std::regex(R"re(SSL_CTX_set_verify\s*\([^,]+,\s*SSL_VERIFY_NONE)re"),
            "TLS certificate verification disabled — CWE-295",
            "Use SSL_VERIFY_PEER with proper CA validation"
        },
        {
            "CYBER008", "CWE-120", Severity::ERROR,
            std::regex(R"re(\bgets\s*\(|\bscanf\s*\(\s*[^,]+,\s*"%[^%]*s")re"),
            "Unbounded input function (gets/scanf without width) — CWE-120",
            "Use fgets() or scanf with explicit field width e.g. \"%255s\""
        },
        {
            "CYBER009", "CWE-190", Severity::WARNING,
            std::regex(R"re(static_cast\s*<\s*(int8_t|uint8_t|int16_t|uint16_t|char|short|unsigned\s+short)\s*>)re"),
            "Integer narrowing conversion — CWE-190 / MISRA 10.3",
            "Verify value fits in target type before narrowing cast"
        },
        {
            "CYBER010", "CWE-89", Severity::ERROR,
            std::regex(R"re((?:query|sql|exec)\s*\+?=\s*(?:user|input|request|argv|param))re", std::regex::icase),
            "String concatenation in SQL/OS API call — CWE-22/CWE-89",
            "Use parameterised queries or validated allowlists"
        },
        {
            "CYBER011", "CWE-120", Severity::ERROR,
            std::regex(R"re(\bstrcpy\s*\(|\bstrcat\s*\(|\bsprintf\s*\(|\bwcscpy\s*\()re"),
            "Unsafe string operation (strcpy/strcat/sprintf) — CWE-120",
            "Use strncpy/strncat/snprintf or std::string"
        },
        {
            "CYBER012", "CWE-476", Severity::WARNING,
            std::regex(R"re(\bnullptr\b.*->|\bNULL\b.*->)re"),
            "Potential null pointer dereference — CWE-476",
            "Check pointer for nullptr before dereferencing"
        },
        {
            "CYBER013", "CWE-416", Severity::WARNING,
            std::regex(R"re(\bfree\s*\([^)]+\)\s*;)re"),
            "free() used — ensure pointer is not accessed after this call (CWE-416)",
            "Set pointer to nullptr after free(); prefer RAII/smart pointers"
        },
        {
            "CYBER014", "CWE-415", Severity::ERROR,
            std::regex(R"re(\bdelete\b[^;]+;[^}]*\bdelete\b)re"),
            "Potential double-free pattern — CWE-415",
            "Set pointer to nullptr after delete; prefer unique_ptr"
        },
        {
            "CYBER015", "CWE-121", Severity::WARNING,
            std::regex(R"re(\balloca\s*\()re"),
            "Stack alloca() usage — variable-length stack allocation — CWE-121",
            "Use std::vector or fixed-size arrays with bounds enforcement"
        },
        {
            "CYBER016", "CWE-732", Severity::WARNING,
            std::regex(R"re((?:chmod|open|creat|mkdir)\s*\([^,)]+,\s*(?:0777|S_IRWXU\s*\|\s*S_IRWXG\s*\|\s*S_IRWXO))re"),
            "Permissive file creation mode (0777) — CWE-732",
            "Use restrictive permissions such as 0640 or 0750"
        },
        {
            "CYBER017", "CWE-798", Severity::WARNING,
            std::regex(R"re(\b(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\.(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\.(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\.(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\b)re"),
            "Hardcoded IP address detected — CWE-798",
            "Load IP addresses from configuration, not source code"
        },
        {
            "CYBER018", "CWE-134", Severity::ERROR,
            std::regex(R"re(\b(?:printf|fprintf|sprintf|vprintf)\s*\(\s*(?!")[^,)])re"),
            "Format string vulnerability — user-controlled format string — CWE-134", // fusa:suppress CYBER018
            "Always use a literal format string: printf(\"%s\", user_str)" // fusa:suppress CYBER018
        },
        {
            "CYBER019", "CWE-362", Severity::WARNING,
            std::regex(R"re(\baccess\s*\()re"),
            "TOCTOU risk: access() followed by open() — CWE-362",
            "Open the file directly and handle ENOENT/EACCES instead of access()"
        },
        {
            "CYBER020", "CWE-377", Severity::ERROR,
            std::regex(R"re(\btmpnam\s*\(|\btempnam\s*\()re"),
            "Insecure temporary file creation (tmpnam/tempnam) — CWE-377",
            "Use mkstemp() or std::filesystem::temp_directory_path() with unique name"
        },
    };
}

} // namespace

//fusa:req REQ-CYBER001
CyberReport run(const fs::path& dir, const config::ProjectConfig& cfg) {
    CyberReport rpt;
    rpt.project      = cfg.project;
    rpt.version      = cfg.version;
    rpt.generated_at = now_iso8601();

    auto rules = build_rules();

    for (const auto& entry : fs::recursive_directory_iterator(
             dir, fs::directory_options::skip_permission_denied)) {
        if (!entry.is_regular_file()) continue;
        if (!is_source(entry.path())) continue;
        if (is_excluded(entry.path(), cfg)) continue;
        // §1.2.1 MUST: honour sourceDirs, not just excludePatterns.
        if (!config::under_source_dirs(entry.path(), dir, cfg)) continue;

        ++rpt.total_files;
        std::ifstream f(entry.path());
        std::string line;
        int lineno = 0;
        while (std::getline(f, line)) {
            ++lineno;
            for (const auto& rule : rules) {
                if (suppressed(line, rule.id)) continue;
                if (std::regex_search(line, rule.re)) {
                    rpt.findings.push_back({
                        rule.id, rule.cwe, rule.sev,
                        rule.message,
                        entry.path().string(), lineno,
                        rule.fix
                    });
                }
            }
        }
    }

    return rpt;
}

Result<std::monostate> write_report(const fs::path& dir, const CyberReport& rpt) {
    auto path = dir / "cyber-report.json";
    json j;
    // §3.1 common header — required on every document.
    j["schemaVersion"] = std::string(SpecVersion);
    j["kind"]          = "cyber-report";
    j["tool"]          = "cpp-FuSa";
    j["toolVersion"]   = std::string(Version);
    j["language"]      = "cpp";
    j["standard"]      = "iso21434";
    j["format"]      = "cpp-FuSa Cyber Report v1";
    j["generatedAt"] = rpt.generated_at;
    j["project"]     = rpt.project;
    j["version"]     = rpt.version;
    j["totalFiles"]  = rpt.total_files;
    j["totalFindings"] = static_cast<int>(rpt.findings.size());

    json fa = json::array();
    for (const auto& f : rpt.findings) {
        json fj;
        fj["ruleId"]   = f.rule_id;
        fj["cwe"]      = f.cwe;
        fj["severity"] = f.severity == Severity::ERROR ? "error"
                       : f.severity == Severity::WARNING ? "warning" : "info";
        fj["message"]  = f.message;
        fj["file"]     = f.file;
        fj["line"]     = f.line;
        fj["fix"]      = f.fix;
        fa.push_back(fj);
    }
    j["findings"] = fa;

    try {
        std::ofstream out(path);
        out << j.dump(2) << "\n";
    } catch (const std::exception& e) {
        return std::string("cyber: write report: ") + e.what();
    }
    return std::monostate{};
}

} // namespace cpfusa::cyber
