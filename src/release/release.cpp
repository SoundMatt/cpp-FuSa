#include "release.hpp"
#include "cpfusa/fusa.hpp"
#include <nlohmann/json.hpp>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <regex>
#include <chrono>
#include <iomanip>
#include <ctime>
#include <cstdio>
#ifndef _WIN32
#  include <fcntl.h>
#  include <sys/wait.h>
#  include <unistd.h>
#endif
#include <array>
#include <algorithm>
#include <cctype>

namespace fs = std::filesystem;
using json   = nlohmann::json;

namespace cpfusa::release {

// Files collected by hash_artifacts and packed by auditpack.
// §1.2 input files + §1.3 generated evidence (fixed filenames only — the
// open-ended `<standard>-gap-report.json` family is matched separately by
// list_present_evidence_files below, since the standard-id set is unbounded).
const std::vector<std::string> EvidenceFiles = {
    // §1.2 input / config files
    ".fusa.json",
    ".fusa-reqs.json",
    ".fusa-hara.json",
    ".fusa-evidence.json",
    ".fusa-dispositions.json",
    ".fusa-problems.json",
    ".fusa-model-trace.json",
    // §1.3 generated evidence
    "check-report.json",
    "cyber-report.json",
    "comp-report.json",
    "coupling-report.json",
    "fmea.json",
    "fmea.csv",
    "boundary.mermaid",
    "boundary.dot",
    "safety-case.json",
    "safety-case.md",
    "safety-case.mermaid",
    "sbom.json",
    "provenance.json",
    "artifact-manifest.json",
    "qualify-report.json",
    "vuln.json",
    "tara.json",
    "tara.md",
};

namespace {

std::string now_iso8601() {
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::ostringstream ss;
    ss << std::put_time(std::gmtime(&t), "%FT%TZ");
    return ss.str();
}

// Minimal SHA-256 — shared with qualify module but inlined here to avoid dep.
// (production code would pull this into a shared utility header)
struct SHA256Ctx2 {
    uint32_t state[8];
    uint64_t count;
    uint8_t  buf[64];
    uint32_t buflen;
};
static const uint32_t K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};
#define R2ROTR(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define R2CH(x,y,z) (((x)&(y))^(~(x)&(z)))
#define R2MAJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
#define R2S0(x) (R2ROTR(x,2)^R2ROTR(x,13)^R2ROTR(x,22))
#define R2S1(x) (R2ROTR(x,6)^R2ROTR(x,11)^R2ROTR(x,25))
#define R2s0(x) (R2ROTR(x,7)^R2ROTR(x,18)^((x)>>3))
#define R2s1(x) (R2ROTR(x,17)^R2ROTR(x,19)^((x)>>10))
static void r2_transform(uint32_t s[8], const uint8_t b[64]) {
    uint32_t w[64],a,bb,c,d,e,f,g,h,t1,t2;
    for(int i=0;i<16;++i) w[i]=(static_cast<uint32_t>(b[i*4])<<24)|(static_cast<uint32_t>(b[i*4+1])<<16)|(static_cast<uint32_t>(b[i*4+2])<<8)|static_cast<uint32_t>(b[i*4+3]);
    for(int i=16;i<64;++i) w[i]=R2s1(w[i-2])+w[i-7]+R2s0(w[i-15])+w[i-16];
    a=s[0];bb=s[1];c=s[2];d=s[3];e=s[4];f=s[5];g=s[6];h=s[7];
    for(int i=0;i<64;++i){t1=h+R2S1(e)+R2CH(e,f,g)+K256[i]+w[i];t2=R2S0(a)+R2MAJ(a,bb,c);h=g;g=f;f=e;e=d+t1;d=c;c=bb;bb=a;a=t1+t2;}
    s[0]+=a;s[1]+=bb;s[2]+=c;s[3]+=d;s[4]+=e;s[5]+=f;s[6]+=g;s[7]+=h;
}
static void r2_init(SHA256Ctx2& ctx) {
    ctx.state[0]=0x6a09e667;ctx.state[1]=0xbb67ae85;ctx.state[2]=0x3c6ef372;ctx.state[3]=0xa54ff53a;
    ctx.state[4]=0x510e527f;ctx.state[5]=0x9b05688c;ctx.state[6]=0x1f83d9ab;ctx.state[7]=0x5be0cd19;
    ctx.count=0;ctx.buflen=0;
}
static void r2_update(SHA256Ctx2& ctx, const uint8_t* data, size_t n) {
    for (size_t i=0;i<n;++i){ctx.buf[ctx.buflen++]=data[i];if(ctx.buflen==64){r2_transform(ctx.state,ctx.buf);ctx.count+=512;ctx.buflen=0;}}
}
static void r2_update_str(SHA256Ctx2& ctx, const std::string& s) {
    r2_update(ctx, reinterpret_cast<const uint8_t*>(s.data()), s.size()); // fusa:unsafe SHA-256 std::string→uint8_t* for FIPS 180-4 input
}
static std::string r2_final_hex(SHA256Ctx2& ctx) {
    ctx.count+=ctx.buflen*8;ctx.buf[ctx.buflen++]=0x80;
    if(ctx.buflen>56){while(ctx.buflen<64)ctx.buf[ctx.buflen++]=0;r2_transform(ctx.state,ctx.buf);ctx.buflen=0;}
    while(ctx.buflen<56)ctx.buf[ctx.buflen++]=0;
    for(int i=7;i>=0;--i)ctx.buf[ctx.buflen++]=(ctx.count>>(i*8))&0xff;
    r2_transform(ctx.state,ctx.buf);
    uint8_t dig[32];
    for(int i=0;i<8;++i){dig[i*4]=(ctx.state[i]>>24)&0xff;dig[i*4+1]=(ctx.state[i]>>16)&0xff;dig[i*4+2]=(ctx.state[i]>>8)&0xff;dig[i*4+3]=ctx.state[i]&0xff;}
    static const char HEX[]="0123456789abcdef";
    std::string out(64,'0');
    for(int i=0;i<32;++i){out[i*2]=HEX[(dig[i]>>4)&0xf];out[i*2+1]=HEX[dig[i]&0xf];}
    return out;
}

static std::string sha256_file(const fs::path& p) {
    SHA256Ctx2 ctx;
    r2_init(ctx);
    std::ifstream f(p, std::ios::binary);
    uint8_t tmp[4096];
    while (f) {
        f.read(reinterpret_cast<char*>(tmp), sizeof(tmp)); // fusa:unsafe SHA-256 FIPS 180-4 binary read
        auto n = static_cast<size_t>(f.gcount());
        r2_update(ctx, tmp, n);
    }
    return r2_final_hex(ctx);
}

// hash_directory_tree computes a single deterministic SHA-256 over every
// regular file under `root` (path sorted, so filesystem enumeration order
// never affects the result): for each file, its root-relative path then its
// raw bytes are folded into the running hash.
std::string hash_directory_tree(const fs::path& root) {
    std::error_code ec;
    if (!fs::exists(root, ec) || !fs::is_directory(root, ec)) return "";
    std::vector<fs::path> files;
    for (auto it = fs::recursive_directory_iterator(
             root, fs::directory_options::skip_permission_denied, ec);
         !ec && it != fs::recursive_directory_iterator(); it.increment(ec)) {
        if (it->is_regular_file()) files.push_back(it->path());
    }
    if (files.empty()) return "";
    std::sort(files.begin(), files.end());

    SHA256Ctx2 ctx;
    r2_init(ctx);
    for (const auto& f : files) {
        auto rel = fs::relative(f, root).generic_string();
        r2_update_str(ctx, rel);
        r2_update(ctx, reinterpret_cast<const uint8_t*>("\x1f"), 1); // fusa:unsafe SHA-256 delimiter byte
        std::ifstream in(f, std::ios::binary);
        uint8_t tmp[4096];
        while (in) {
            in.read(reinterpret_cast<char*>(tmp), sizeof(tmp)); // fusa:unsafe SHA-256 FIPS 180-4 binary read
            auto n = static_cast<size_t>(in.gcount());
            r2_update(ctx, tmp, n);
        }
    }
    return r2_final_hex(ctx);
}

// hash_fetched_source_tree looks for an already-fetched CMake FetchContent
// source tree for dependency `name` (CMake places it at
// `<binary-dir>/_deps/<lowercase-name>-src`) under any top-level directory of
// `project_root`, and hashes it via hash_directory_tree. Returns "" when no
// fetched tree can be found (e.g. a clean checkout that hasn't been
// configured/built yet) — callers MUST treat that as "no hash available",
// never fabricate one.
std::string hash_fetched_source_tree(const fs::path& project_root, const std::string& name) {
    std::string lower = name;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                    [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    std::error_code ec;
    for (auto it = fs::directory_iterator(project_root, ec); !ec && it != fs::directory_iterator();
         it.increment(ec)) {
        if (!it->is_directory()) continue;
        auto candidate = it->path() / "_deps" / (lower + "-src");
        auto h = hash_directory_tree(candidate);
        if (!h.empty()) return h;
    }
    return "";
}

// Runs a command as an argv vector WITHOUT a shell, capturing stdout. Using
// execvp (never a shell-interpolated command string) means a caller-supplied
// path (e.g. --dir → project_root, itself untrusted input) is always passed
// as a single literal argument and can never be interpreted as shell syntax
// — closes the same CWE-78 command-injection class as cpp-FuSa-V01
// (impact.cpp) / cpp-FuSa-V03 (auditpack.cpp), which this function's prior
// shell-based implementation reintroduced here via
// `"git -C \"" + project_root.string() + "\" ..."` string interpolation.
std::string run_argv(const std::vector<std::string>& args) {
    std::string result;
    if (args.empty()) return result;
#ifdef _WIN32
    // Fall back to a quoted command line on Windows (no fork/exec), still
    // quoting each argument individually rather than interpolating raw text.
    std::string cmd;
    for (const auto& a : args) {
        if (!cmd.empty()) cmd += ' ';
        cmd += '"';
        for (char ch : a) { if (ch == '"') cmd += '\\'; cmd += ch; }
        cmd += '"';
    }
    FILE* pipe = _popen(cmd.c_str(), "r");
    if (!pipe) return result;
    std::array<char, 256> buf{};
    while (fgets(buf.data(), static_cast<int>(buf.size()), pipe))
        result += buf.data();
    _pclose(pipe);
    while (!result.empty() && (result.back()=='\n'||result.back()=='\r')) result.pop_back();
    return result;
#else
    int fds[2];
    if (pipe(fds) != 0) return result;
    pid_t pid = fork();
    if (pid < 0) { close(fds[0]); close(fds[1]); return result; }
    if (pid == 0) {
        // Child: stdout → pipe, stderr → /dev/null, then exec (no shell).
        dup2(fds[1], STDOUT_FILENO);
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) { dup2(devnull, STDERR_FILENO); close(devnull); }
        close(fds[0]);
        close(fds[1]);
        std::vector<char*> argv;
        argv.reserve(args.size() + 1);
        for (const auto& a : args) argv.push_back(const_cast<char*>(a.c_str()));
        argv.push_back(nullptr);
        execvp(argv[0], argv.data());
        _exit(127);
    }
    close(fds[1]);
    std::array<char, 256> buf{};
    ssize_t n;
    while ((n = read(fds[0], buf.data(), buf.size())) > 0)
        result.append(buf.data(), static_cast<size_t>(n));
    close(fds[0]);
    int status = 0;
    waitpid(pid, &status, 0);
    // trim trailing newline
    while (!result.empty() && (result.back()=='\n'||result.back()=='\r')) result.pop_back();
    return result;
#endif
}

// Parse FetchContent_Declare blocks from cmake file.
std::vector<Component> parse_cmake_deps(const fs::path& cmake_file) {
    std::vector<Component> comps;
    if (!fs::exists(cmake_file)) return comps;
    std::ifstream f(cmake_file);
    std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());

    static const std::regex decl_re(
        R"re(FetchContent_Declare\s*\(\s*(\w+)[^)]*GIT_TAG\s+v?([\w.\-]+))re");
    auto begin = std::sregex_iterator(content.begin(), content.end(), decl_re);
    auto end   = std::sregex_iterator();
    for (auto it = begin; it != end; ++it) {
        comps.push_back({(*it)[1].str(), (*it)[2].str(), ""});
    }
    return comps;
}

} // namespace

SpdxVersion parse_spdx_version(const std::string& s) {
    if (s == "2.2") return SpdxVersion::V2_2;
    if (s == "2.3") return SpdxVersion::V2_3;
    return SpdxVersion::V3_0_1;
}

//fusa:req REQ-RELEASE009
void write_sbom(const fs::path& out, const SBOM& sbom, SpdxVersion ver) {
    json j;
    if (ver == SpdxVersion::V2_2 || ver == SpdxVersion::V2_3) {
        std::string ver_str = (ver == SpdxVersion::V2_2) ? "SPDX-2.2" : "SPDX-2.3";
        j["spdxVersion"]  = ver_str;
        j["SPDXID"]       = "SPDXRef-DOCUMENT";
        j["name"]         = sbom.project;
        j["dataLicense"]  = "CC0-1.0";
        j["documentNamespace"] = "https://github.com/SoundMatt/cpp-FuSa/sbom/" + sbom.project;
        j["creationInfo"] = {{"created", sbom.generated_at},
                              {"creators", json::array({"Tool: cpp-FuSa"})}};
        json pkgs = json::array();
        for (const auto& c : sbom.components) {
            pkgs.push_back({
                {"SPDXID",       "SPDXRef-" + c.name},
                {"name",         c.name},
                {"versionInfo",  c.version},
                {"downloadLocation", "NOASSERTION"},
                {"filesAnalyzed", false}
            });
        }
        j["packages"]      = pkgs;
        j["relationships"] = json::array();
    } else {
        // SPDX 3.0.1 / cpp-FuSa SBOM v1 format
        j["schemaVersion"] = std::string(SpecVersion);
        j["kind"]          = "sbom";
        j["tool"]          = "cpp-FuSa";
        j["toolVersion"]   = std::string(Version);
        j["language"]      = "cpp";
        j["generatedAt"]   = sbom.generated_at;
        j["format"]        = "x-FuSa SBOM v1";
        j["module"]        = "github.com/SoundMatt/cpp-FuSa";
        json cs = json::array();
        for (const auto& c : sbom.components) {
            json cj;
            cj["name"]    = c.name;
            cj["version"] = c.version;
            // §7/§2.7: hash MUST be "algo:value" when present; a component
            // with no computable hash omits the key rather than emitting "".
            if (!c.hash.empty()) cj["hash"] = "sha256:" + c.hash;
            cs.push_back(cj);
        }
        j["components"] = cs;
    }
    std::ofstream f(out);
    f << j.dump(2) << "\n";
}

//fusa:req REQ-RELEASE001 REQ-RELEASE002 REQ-RELEASE003 REQ-RELEASE004 REQ-RELEASE007 REQ-RELEASE008
Result<SBOM> build_sbom(const fs::path& project_root, const config::ProjectConfig& cfg) {
    SBOM sbom;
    sbom.format       = "cpp-FuSa SBOM v1";
    sbom.generated_at = now_iso8601();
    sbom.project      = cfg.project;
    sbom.cpp_version  = cfg.language;

    // Try to get CMake version — first line of `cmake --version`'s output,
    // taken in-process (run_argv, no shell) rather than piping through `head`.
    {
        auto out = run_argv({"cmake", "--version"});
        auto nl  = out.find('\n');
        sbom.cmake_version = (nl == std::string::npos) ? out : out.substr(0, nl);
    }

    // Parse dependencies from cmake/FetchDeps.cmake
    sbom.components = parse_cmake_deps(project_root / "cmake" / "FetchDeps.cmake");
    // Also try CMakeLists.txt
    if (sbom.components.empty()) {
        sbom.components = parse_cmake_deps(project_root / "CMakeLists.txt");
    }

    // §7: components[].hash, when present, MUST be "sha256:<hex>" of real
    // content — never a fabricated or empty placeholder. If this dependency
    // has already been fetched by a prior CMake configure (build/_deps/...),
    // hash that real source tree; otherwise leave Component.hash empty so
    // the "hash" key is omitted entirely rather than emitted as "".
    for (auto& c : sbom.components) {
        c.hash = hash_fetched_source_tree(project_root, c.name);
    }

    return sbom;
}

//fusa:req REQ-RELEASE005 REQ-RELEASE007
Result<Provenance> build_provenance(const fs::path& project_root,
                                    const config::ProjectConfig& cfg) {
    Provenance prov;
    prov.format       = "cpp-FuSa Provenance v1";
    prov.generated_at = now_iso8601();
    prov.project      = cfg.project;
    prov.cpp_version  = cfg.language;

    // Platform info
#if defined(__APPLE__)
    prov.platform = "darwin";
#elif defined(_WIN32)
    prov.platform = "windows";
#else
    prov.platform = "linux";
#endif

    // VCS info. project_root comes from --dir (untrusted input, exactly like
    // cpp-FuSa-V01/V03) — run_argv passes it as a literal argv entry rather
    // than interpolating it into a shell string, so it can never be used to
    // inject additional commands (CWE-78).
    auto rev = run_argv({"git", "-C", project_root.string(), "rev-parse", "HEAD"});
    if (!rev.empty()) {
        prov.vcs_revision = rev;
        auto status = run_argv({"git", "-C", project_root.string(), "status", "--porcelain"});
        prov.vcs_modified = !status.empty();
    }

    return prov;
}

//fusa:req REQ-RELEASE006 REQ-AUDIT001
std::vector<std::string> list_present_evidence_files(const fs::path& dir) {
    std::vector<std::string> found;
    for (const auto& name : EvidenceFiles)
        if (fs::exists(dir / name)) found.push_back(name);

    // §1.3: `<standard>-gap-report.json` — the standard-id set is
    // open-ended (iso26262, iec61508, iso21434, do178, misra-cpp,
    // unece-r155, iec62443, slsa, ...), so scan for it rather than
    // hardcoding every known standard id.
    static const std::regex gap_report_re(R"(^[a-z0-9][a-z0-9\-]*-gap-report\.json$)");
    std::error_code ec;
    for (auto it = fs::directory_iterator(dir, fs::directory_options::skip_permission_denied, ec);
         !ec && it != fs::directory_iterator(); it.increment(ec)) {
        if (!it->is_regular_file()) continue;
        auto fname = it->path().filename().string();
        if (std::regex_match(fname, gap_report_re)) found.push_back(fname);
    }

    std::sort(found.begin(), found.end());
    found.erase(std::unique(found.begin(), found.end()), found.end());
    return found;
}

//fusa:req REQ-RELEASE006
Manifest hash_artifacts(const fs::path& dir) {
    Manifest m;
    m.format       = "cpp-FuSa Artifact Manifest v1";
    m.generated_at = now_iso8601();
    for (const auto& name : list_present_evidence_files(dir)) {
        auto p = dir / name;
        Artifact a;
        a.path   = name;
        a.sha256 = sha256_file(p);
        m.artifacts.push_back(a);
    }
    return m;
}

Result<std::monostate> write_all(const fs::path& dir,
                                 const SBOM& sbom,
                                 const Provenance& prov,
                                 const Manifest& manifest) {
    try {
        // sbom.json — §7 spec-conformant with §3.1 common header
        {
            json j;
            j["schemaVersion"] = std::string(SpecVersion);
            j["kind"]          = "sbom";
            j["tool"]          = "cpp-FuSa";
            j["toolVersion"]   = std::string(Version);
            j["language"]      = "cpp";
            j["generatedAt"]   = sbom.generated_at;
            j["format"]        = "x-FuSa SBOM v1";
            // §7: module = repo URL or <project>@<version> for ecosystems without a module path
            j["module"]        = "github.com/SoundMatt/cpp-FuSa";
            json cs = json::array();
            for (const auto& c : sbom.components) {
                json cj;
                cj["name"]    = c.name;
                cj["version"] = c.version;
                // §7: hash MUST be "algo:value"; §2.7: named hash field uses
                // algo:value prefix. Omit the key entirely when no real hash
                // is available rather than emit a schema-violating "".
                if (!c.hash.empty()) cj["hash"] = "sha256:" + c.hash;
                cs.push_back(cj);
            }
            j["components"] = cs;
            std::ofstream out(dir / SBOMFile);
            out << j.dump(2) << "\n";
        }
        // provenance.json — §7 with §3.1 common header
        {
            json j;
            j["schemaVersion"] = std::string(SpecVersion);
            j["kind"]          = "provenance";
            j["tool"]          = "cpp-FuSa";
            j["toolVersion"]   = std::string(Version);
            j["language"]      = "cpp";
            j["generatedAt"]   = prov.generated_at;
            j["format"]        = "x-FuSa provenance v1";
            j["module"]        = "github.com/SoundMatt/cpp-FuSa";
            j["builder"]       = "local";
            j["vcsRevision"]   = prov.vcs_revision;
            j["vcsModified"]   = prov.vcs_modified;
            j["os"]            = prov.platform;
            std::ofstream out(dir / ProvenanceFile);
            out << j.dump(2) << "\n";
        }
        // artifact-manifest.json — §7 with §3.1 common header
        {
            json j;
            j["schemaVersion"] = std::string(SpecVersion);
            j["kind"]          = "artifact-manifest";
            j["tool"]          = "cpp-FuSa";
            j["toolVersion"]   = std::string(Version);
            j["language"]      = "cpp";
            j["generatedAt"]   = manifest.generated_at;
            j["format"]        = "x-FuSa manifest v1";
            json ar = json::array();
            for (const auto& a : manifest.artifacts)
                ar.push_back({{"path", a.path}, {"sha256", a.sha256}});
            j["artifacts"] = ar;
            std::ofstream out(dir / ManifestFile);
            out << j.dump(2) << "\n";
        }
    } catch (const std::exception& e) {
        return std::string("release: write: ") + e.what();
    }
    return std::monostate{};
}

} // namespace cpfusa::release
