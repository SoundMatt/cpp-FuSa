#include "qualify.hpp"
#include <nlohmann/json.hpp>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <chrono>
#include <iomanip>
#include <ctime>
#include <cstdio>
#include <cstring>
#include <atomic>

namespace fs = std::filesystem;
using json   = nlohmann::json;

namespace cpfusa::qualify {

namespace {

std::string now_iso8601() {
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::ostringstream ss;
    ss << std::put_time(std::gmtime(&t), "%FT%TZ");
    return ss.str();
}

// Minimal SHA-256 implementation (FIPS PUB 180-4).
// Used only for the qualify-report integrity hash.
struct SHA256Ctx {
    uint32_t state[8];
    uint64_t count;
    uint8_t  buf[64];
    uint32_t buflen;
};

static const uint32_t k256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define ROTR32(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define CH(x,y,z)   (((x)&(y))^(~(x)&(z)))
#define MAJ(x,y,z)  (((x)&(y))^((x)&(z))^((y)&(z)))
#define S0(x)       (ROTR32(x,2)^ROTR32(x,13)^ROTR32(x,22))
#define S1(x)       (ROTR32(x,6)^ROTR32(x,11)^ROTR32(x,25))
#define s0(x)       (ROTR32(x,7)^ROTR32(x,18)^((x)>>3))
#define s1(x)       (ROTR32(x,17)^ROTR32(x,19)^((x)>>10))

static void sha256_transform(uint32_t state[8], const uint8_t block[64]) {
    uint32_t w[64], a,b,c,d,e,f,g,h,t1,t2;
    for (int i = 0; i < 16; ++i)
        w[i] = (static_cast<uint32_t>(block[i*4])<<24)|(static_cast<uint32_t>(block[i*4+1])<<16)|
               (static_cast<uint32_t>(block[i*4+2])<<8)|static_cast<uint32_t>(block[i*4+3]);
    for (int i = 16; i < 64; ++i)
        w[i] = s1(w[i-2]) + w[i-7] + s0(w[i-15]) + w[i-16];
    a=state[0]; b=state[1]; c=state[2]; d=state[3];
    e=state[4]; f=state[5]; g=state[6]; h=state[7];
    for (int i = 0; i < 64; ++i) {
        t1 = h + S1(e) + CH(e,f,g) + k256[i] + w[i];
        t2 = S0(a) + MAJ(a,b,c);
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    state[0]+=a; state[1]+=b; state[2]+=c; state[3]+=d;
    state[4]+=e; state[5]+=f; state[6]+=g; state[7]+=h;
}

static void sha256_init(SHA256Ctx& ctx) {
    ctx.state[0]=0x6a09e667; ctx.state[1]=0xbb67ae85;
    ctx.state[2]=0x3c6ef372; ctx.state[3]=0xa54ff53a;
    ctx.state[4]=0x510e527f; ctx.state[5]=0x9b05688c;
    ctx.state[6]=0x1f83d9ab; ctx.state[7]=0x5be0cd19;
    ctx.count=0; ctx.buflen=0;
}

static void sha256_update(SHA256Ctx& ctx, const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        ctx.buf[ctx.buflen++] = data[i]; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
        if (ctx.buflen == 64) {
            sha256_transform(ctx.state, ctx.buf);
            ctx.count += 512;
            ctx.buflen = 0;
        }
    }
}

static void sha256_final(SHA256Ctx& ctx, uint8_t digest[32]) {
    ctx.count += ctx.buflen * 8;
    ctx.buf[ctx.buflen++] = 0x80;
    if (ctx.buflen > 56) {
        while (ctx.buflen < 64) ctx.buf[ctx.buflen++] = 0;
        sha256_transform(ctx.state, ctx.buf);
        ctx.buflen = 0;
    }
    while (ctx.buflen < 56) ctx.buf[ctx.buflen++] = 0;
    for (int i = 7; i >= 0; --i) {
        ctx.buf[ctx.buflen++] = (ctx.count >> (i * 8)) & 0xff;
    }
    sha256_transform(ctx.state, ctx.buf);
    for (int i = 0; i < 8; ++i) {
        digest[i*4]   = (ctx.state[i]>>24) & 0xff;
        digest[i*4+1] = (ctx.state[i]>>16) & 0xff;
        digest[i*4+2] = (ctx.state[i]>>8)  & 0xff;
        digest[i*4+3] =  ctx.state[i]       & 0xff;
    }
}

std::string sha256_hex(const std::string& data) {
    SHA256Ctx ctx;
    sha256_init(ctx);
    sha256_update(ctx, reinterpret_cast<const uint8_t*>(data.data()), data.size()); // fusa:unsafe SHA-256 std::string→uint8_t* for FIPS 180-4 input
    uint8_t digest[32];
    sha256_final(ctx, digest);
    static const char hex[] = "0123456789abcdef";
    std::string out(64, '0');
    for (int i = 0; i < 32; ++i) {
        out[i*2]   = hex[(digest[i]>>4)&0xf];
        out[i*2+1] = hex[digest[i]&0xf];
    }
    return out;
}

// Compute hash of the report without the hash field.
std::string compute_hash(const QualifyReport& r) {
    json j;
    j["generatedAt"] = r.generated_at;
    j["cppVersion"]  = r.cpp_version;
    j["module"]      = r.module;
    j["total"]       = r.total;
    j["passed"]      = r.passed;
    j["failed"]      = r.failed;
    json ra = json::array();
    for (const auto& cr : r.results) {
        json rj;
        rj["case"]["name"]         = cr.test_case.name;
        rj["case"]["ruleId"]       = cr.test_case.rule_id;
        rj["case"]["description"]  = cr.test_case.description;
        rj["case"]["expectFinding"]= cr.test_case.expect_finding;
        rj["passed"]               = cr.passed;
        if (!cr.error.empty()) rj["error"] = cr.error;
        ra.push_back(rj);
    }
    j["results"] = ra;
    return sha256_hex(j.dump());
}

// Run a single qualification case against a TempDir synthetic project.
//fusa:req REQ-QUALIFY003
CaseResult run_case(const Case& c) {
    // Create temp dir using unique counter + high-res clock for isolation.
    fs::path tmp;
    try {
        static std::atomic<int> counter{0};
        auto tick = std::chrono::steady_clock::now().time_since_epoch().count();
        auto name = std::string("cpfusa-qualify-")
                  + std::to_string(tick) + "-"
                  + std::to_string(counter.fetch_add(1));
        tmp = fs::temp_directory_path() / name;
        fs::create_directories(tmp);
    } catch (...) {
        return {c, false, "failed to create temp directory"};
    }

    // Write synthetic files (do NOT automatically write .fusa.json — the case
    // controls whether it is present, so FUSA001 tests work correctly).
    try {
        for (const auto& [rel, content] : c.files) {
            auto p = tmp / rel;
            fs::create_directories(p.parent_path());
            std::ofstream f(p);
            f << content;
        }
    } catch (const std::exception& e) {
        fs::remove_all(tmp);
        return {c, false, std::string("write files: ") + e.what()};
    }

    // Build a default config and run the engine directly (no file load needed).
    bool found_rule = false;
    try {
        config::ProjectConfig cfg;
        cfg.project          = "qualify-test";
        cfg.version          = "0.0.0";
        cfg.standard         = "iso26262";
        cfg.asil             = "B";
        cfg.language         = "cpp17";
        cfg.source_dirs      = {"src"};
        cfg.exclude_patterns = {};
        cfg.strict           = false;
        auto eng      = engine::make_default_engine();
        auto findings = eng.run(tmp, cfg);
        for (const auto& f : findings) {
            if (f.rule_id == c.rule_id) { found_rule = true; break; }
        }
    } catch (const std::exception& e) {
        fs::remove_all(tmp);
        return {c, false, std::string("engine run: ") + e.what()};
    }

    fs::remove_all(tmp);

    if (found_rule == c.expect_finding) return {c, true, ""};
    if (c.expect_finding)
        return {c, false, "expected finding " + c.rule_id + " but none produced"};
    return {c, false, "unexpected finding " + c.rule_id + " was produced"};
}

} // namespace

//fusa:req REQ-QUALIFY001 REQ-QUALIFY002 REQ-QUALIFY004
std::vector<Case> builtin_cases() {
    return {
        // FUSA001: .fusa.json must exist
        {
            "FUSA001-positive", "FUSA001",
            "Missing .fusa.json triggers FUSA001 finding",
            {{"src/main.cpp", "int main(){return 0;}"}},
            // No .fusa.json in files — engine runs with default config, rule fires.
            true
        },
        {
            "FUSA001-negative", "FUSA001",
            ".fusa.json present — no FUSA001 finding",
            {
                {"src/main.cpp", "//fusa:req REQ-001\nint main(){return 0;}"},
                {".fusa.json", "{\"project\":\"q\",\"version\":\"1.0.0\",\"standard\":\"iso26262\","
                               "\"asil\":\"B\",\"language\":\"cpp17\",\"source_dirs\":[\"src\"],"
                               "\"exclude_patterns\":[],\"strict\":false}"}
            },
            false
        },
        // FUSA002: at least one //fusa:req annotation
        {
            "FUSA002-positive", "FUSA002",
            "No //fusa:req annotation triggers FUSA002",
            {
                {"src/main.cpp", "int main(){return 0;}"},
                {".fusa.json", "{\"project\":\"q\",\"version\":\"1.0.0\",\"standard\":\"iso26262\","
                               "\"asil\":\"B\",\"language\":\"cpp17\",\"source_dirs\":[\"src\"],"
                               "\"exclude_patterns\":[],\"strict\":false}"}
            },
            true
        },
        {
            "FUSA002-negative", "FUSA002",
            "//fusa:req annotation present — no FUSA002",
            {
                {"src/main.cpp", "//fusa:req REQ-001\nint main(){return 0;}"},
                {".fusa.json", "{\"project\":\"q\",\"version\":\"1.0.0\",\"standard\":\"iso26262\","
                               "\"asil\":\"B\",\"language\":\"cpp17\",\"source_dirs\":[\"src\"],"
                               "\"exclude_patterns\":[],\"strict\":false}"}
            },
            false
        },
        // FUSA003: version set and not 0.0.0
        {
            "FUSA003-positive", "FUSA003",
            "version=0.0.0 (default config) triggers FUSA003",
            // Default config has version=0.0.0, so FUSA003 fires.
            {{"src/main.cpp", "//fusa:req REQ-001\nint main(){return 0;}"}},
            true
        },
        // FUSA004: .fusa-evidence.json present
        {
            "FUSA004-positive", "FUSA004",
            "Missing .fusa-evidence.json triggers FUSA004",
            {{"src/main.cpp", "//fusa:req REQ-001\nint main(){return 0;}"}},
            true
        },
        // FUSA005: CHANGELOG.md present
        {
            "FUSA005-positive", "FUSA005",
            "Missing CHANGELOG.md triggers FUSA005",
            {{"src/main.cpp", "//fusa:req REQ-001\nint main(){return 0;}"}},
            true
        },
        {
            "FUSA005-negative", "FUSA005",
            "CHANGELOG.md present — no FUSA005",
            {
                {"src/main.cpp", "//fusa:req REQ-001\nint main(){return 0;}"},
                {"CHANGELOG.md", "# Changelog\n## v0.1.0\nInitial release\n"}
            },
            false
        },
    };
}

//fusa:req REQ-QUALIFY002 REQ-QUALIFY003
Result<QualifyReport> run(const std::vector<Case>& cases) {
    QualifyReport report;
    report.generated_at = now_iso8601();
    report.cpp_version  = "C++17";
    report.module       = "github.com/SoundMatt/cpp-FuSa";

    for (const auto& c : cases) {
        auto cr = run_case(c);
        ++report.total;
        if (cr.passed) ++report.passed; else ++report.failed;
        report.results.push_back(std::move(cr));
    }

    report.hash = compute_hash(report);
    return report;
}

Result<std::monostate> save(const fs::path& path, const QualifyReport& r) {
    json j;
    // §3.1 common header
    j["schemaVersion"] = std::string(SpecVersion);
    j["kind"]          = "qualification";
    j["tool"]          = "cpp-FuSa";
    j["toolVersion"]   = std::string(Version);
    j["language"]      = "cpp";
    j["generatedAt"]   = r.generated_at;
    // §6 qualify payload
    j["module"]        = r.module;
    j["total"]         = r.total;
    j["passed"]        = r.passed;
    j["failed"]        = r.failed;
    json ra = json::array();
    for (const auto& cr : r.results) {
        json rj;
        json cj;
        cj["name"]          = cr.test_case.name;
        cj["ruleId"]        = cr.test_case.rule_id;
        cj["description"]   = cr.test_case.description;
        cj["expectFinding"] = cr.test_case.expect_finding;
        rj["case"]   = cj;
        rj["passed"] = cr.passed;
        if (!cr.error.empty()) rj["error"] = cr.error;
        ra.push_back(rj);
    }
    j["results"] = ra;
    j["hash"]    = r.hash;

    // Feature 2: tool qualification display fields (REQ-QUALIFY005..REQ-QUALIFY007)
    if (!r.qualification_method.empty())
        j["qualificationMethod"]    = r.qualification_method;
    if (!r.qualification_record_uri.empty())
        j["qualificationRecordUri"] = r.qualification_record_uri;
    if (!r.qualifier_identity.empty())
        j["qualifierIdentity"]      = r.qualifier_identity;

    // Feature 4: V&V independence fields (REQ-QUALIFY008..REQ-QUALIFY010)
    if (!r.implementation_author.empty())
        j["implementationAuthor"]     = r.implementation_author;
    if (!r.independent_reviewer.empty())
        j["independentReviewer"]      = r.independent_reviewer;
    if (!r.independent_test_executor.empty())
        j["independentTestExecutor"]  = r.independent_test_executor;
    if (!r.achievable_asil.empty())
        j["achievableAsil"]           = r.achievable_asil;

    // Always emit independence status and badge when identity info is present
    std::string status = r.independence_status();
    if (status != "unqualified" || !r.qualification_method.empty()) {
        j["independenceStatus"] = status;
        // Badge: independently-qualified > self-qualified > unqualified
        std::string badge;
        if (r.qualification_method == "independent" || status == "independent")
            badge = "independently-qualified";
        else if (r.qualification_method == "self" || status == "self")
            badge = "self-qualified";
        else
            badge = "unqualified";
        j["badge"] = badge;
    }

    try {
        std::ofstream out(path);
        out << j.dump(2) << "\n";
    } catch (const std::exception& e) {
        return std::string("qualify: save: ") + e.what();
    }
    return std::monostate{};
}

} // namespace cpfusa::qualify
