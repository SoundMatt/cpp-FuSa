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
#ifdef _WIN32
#  define popen  _popen
#  define pclose _pclose
#endif
#include <array>

namespace fs = std::filesystem;
using json   = nlohmann::json;

namespace cpfusa::release {

// Files collected by hash_artifacts and packed by auditpack.
const std::vector<std::string> EvidenceFiles = {
    ".fusa.json",
    ".fusa-reqs.json",
    ".fusa-evidence.json",
    "check-report.json",
    "cyber-report.json",
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
static std::string sha256_file(const fs::path& p) {
    SHA256Ctx2 ctx;
    ctx.state[0]=0x6a09e667;ctx.state[1]=0xbb67ae85;ctx.state[2]=0x3c6ef372;ctx.state[3]=0xa54ff53a;
    ctx.state[4]=0x510e527f;ctx.state[5]=0x9b05688c;ctx.state[6]=0x1f83d9ab;ctx.state[7]=0x5be0cd19;
    ctx.count=0;ctx.buflen=0;
    std::ifstream f(p, std::ios::binary);
    uint8_t tmp[4096];
    while (f) {
        f.read(reinterpret_cast<char*>(tmp), sizeof(tmp)); // fusa:unsafe SHA-256 FIPS 180-4 binary read
        auto n = static_cast<size_t>(f.gcount());
        for (size_t i=0;i<n;++i){ctx.buf[ctx.buflen++]=tmp[i];if(ctx.buflen==64){r2_transform(ctx.state,ctx.buf);ctx.count+=512;ctx.buflen=0;}}
    }
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

std::string run_cmd_str(const std::string& cmd) {
    std::string out;
    std::array<char,256> buf{};
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return out;
    while (fgets(buf.data(), static_cast<int>(buf.size()), pipe)) out += buf.data();
    pclose(pipe);
    // trim trailing newline
    while (!out.empty() && (out.back()=='\n'||out.back()=='\r')) out.pop_back();
    return out;
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

//fusa:req REQ-RELEASE001 REQ-RELEASE002 REQ-RELEASE003 REQ-RELEASE004 REQ-RELEASE007 REQ-RELEASE008
Result<SBOM> build_sbom(const fs::path& project_root, const config::ProjectConfig& cfg) {
    SBOM sbom;
    sbom.format       = "cpp-FuSa SBOM v1";
    sbom.generated_at = now_iso8601();
    sbom.project      = cfg.project;
    sbom.cpp_version  = cfg.language;

    // Try to get CMake version
    sbom.cmake_version = run_cmd_str("cmake --version 2>/dev/null | head -1");

    // Parse dependencies from cmake/FetchDeps.cmake
    sbom.components = parse_cmake_deps(project_root / "cmake" / "FetchDeps.cmake");
    // Also try CMakeLists.txt
    if (sbom.components.empty()) {
        sbom.components = parse_cmake_deps(project_root / "CMakeLists.txt");
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

    // VCS info
    auto rev = run_cmd_str("git -C \"" + project_root.string() + "\" rev-parse HEAD 2>/dev/null");
    if (!rev.empty()) {
        prov.vcs_revision = rev;
        auto status = run_cmd_str("git -C \"" + project_root.string() + "\" status --porcelain 2>/dev/null");
        prov.vcs_modified = !status.empty();
    }

    return prov;
}

//fusa:req REQ-RELEASE006
Manifest hash_artifacts(const fs::path& dir) {
    Manifest m;
    m.format       = "cpp-FuSa Artifact Manifest v1";
    m.generated_at = now_iso8601();
    for (const auto& name : EvidenceFiles) {
        auto p = dir / name;
        if (!fs::exists(p)) continue;
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
                // §7: hash MUST be "algo:value"; §2.7: named hash field uses algo:value prefix
                cj["hash"] = c.hash.empty() ? "" : ("sha256:" + c.hash);
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
