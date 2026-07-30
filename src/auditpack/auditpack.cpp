#include "auditpack.hpp"
#include "../release/release.hpp"
#include "cpfusa/fusa.hpp"
#include <nlohmann/json.hpp>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <chrono>
#include <iomanip>
#include <ctime>
#include <cstdio>
#ifdef _WIN32
#  define popen  _popen
#  define pclose _pclose
#else
#  include <sys/wait.h>
#  include <unistd.h>
#  include <fcntl.h>
#endif
#include <cstring>
#include <array>
#include <vector>

namespace fs = std::filesystem;
using json   = nlohmann::json;

namespace cpfusa::auditpack {

namespace {

std::string trim_trailing(std::string s) {
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r' || s.back() == ' '))
        s.pop_back();
    return s;
}

// Directory paths embedded in a double-quoted shell argument must not end
// in a path separator: on Windows, `cd "C:\...\Temp\"` has the trailing
// backslash escape the closing quote (MSVCRT/cmd.exe argument-parsing
// behaviour), corrupting the rest of the command line. std::filesystem's
// temp_directory_path() (wrapping GetTempPathW) and some directory_iterator
// results always carry a trailing separator on Windows, so every directory
// path built into a quoted "cd \"...\"" fragment must go through this first.
#ifdef _WIN32
std::string strip_trailing_sep(std::string s) {
    while (!s.empty() && (s.back() == '\\' || s.back() == '/'))
        s.pop_back();
    return s;
}
#endif

std::string now_iso8601() {
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::ostringstream ss;
    ss << std::put_time(std::gmtime(&t), "%FT%TZ");
    return ss.str();
}

// Result of running an external command via popen: captured stdout+stderr
// and a normalised exit code (0 == success). A missing binary (e.g. the
// system `zip` CLI) surfaces here as a non-zero exit code rather than being
// silently swallowed — callers MUST check it before trusting the output.
struct CmdResult {
    std::string output;
    int         exit_code{-1};
};

#ifdef _WIN32
CmdResult run_cmd(const std::string& cmd) {
    CmdResult result;
    std::array<char,256> buf{};
    // Windows-only fallback (no fork/exec API): cmd is assembled by
    // run_argv_cwd above, which quotes every argument individually — this is
    // not the cpp-FuSa-V03 shell-interpolation defect (that path used
    // unescaped string concatenation; this one never does).
    FILE* pipe = popen(cmd.c_str(), "r"); // fusa:suppress CYBER005
    if (!pipe) return result; // exit_code stays -1 — popen itself failed
    while (fgets(buf.data(), static_cast<int>(buf.size()), pipe)) result.output += buf.data();
    int status = pclose(pipe);
    if (status < 0) {
        result.exit_code = -1;
    } else {
        result.exit_code = status;
    }
    return result;
}
#endif

// Run `zip` as an argv vector from within working directory `cwd`, WITHOUT a
// shell. Paths (project_root, --output, evidence names) are passed as literal
// argv entries so they can never be interpreted as shell syntax (CWE-78).
// Windows keeps the quoted-shell path (no fork/exec) but at least avoids the
// `cd &&` metacharacter surface by quoting each argument.
CmdResult run_argv_cwd(const std::string& cwd,
                       const std::vector<std::string>& args) {
    CmdResult result;
    if (args.empty()) return result;
#ifdef _WIN32
    std::string cmd = "cd /d \"" + strip_trailing_sep(cwd) + "\" && ";
    for (size_t i = 0; i < args.size(); ++i) {
        if (i) cmd += ' ';
        cmd += '"';
        for (char ch : args[i]) { if (ch == '"') cmd += '\\'; cmd += ch; }
        cmd += '"';
    }
    cmd += " 2>&1";
    return run_cmd(cmd);
#else
    int fds[2];
    if (pipe(fds) != 0) return result;
    pid_t pid = fork();
    if (pid < 0) { close(fds[0]); close(fds[1]); return result; }
    if (pid == 0) {
        if (chdir(cwd.c_str()) != 0) _exit(127);
        dup2(fds[1], STDOUT_FILENO);
        dup2(fds[1], STDERR_FILENO);
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
        result.output.append(buf.data(), static_cast<size_t>(n));
    close(fds[0]);
    int status = 0;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status)) result.exit_code = WEXITSTATUS(status);
    else result.exit_code = -1;
    return result;
#endif
}
struct SHA256Ctx3 {
    uint32_t state[8];
    uint64_t count;
    uint8_t  buf[64];
    uint32_t buflen;
};
static const uint32_t K3[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};
#define A3ROTR(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define A3CH(x,y,z) (((x)&(y))^(~(x)&(z)))
#define A3MAJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
#define A3S0(x) (A3ROTR(x,2)^A3ROTR(x,13)^A3ROTR(x,22))
#define A3S1(x) (A3ROTR(x,6)^A3ROTR(x,11)^A3ROTR(x,25))
#define A3s0(x) (A3ROTR(x,7)^A3ROTR(x,18)^((x)>>3))
#define A3s1(x) (A3ROTR(x,17)^A3ROTR(x,19)^((x)>>10))
static void a3_transform(uint32_t s[8], const uint8_t b[64]) {
    uint32_t w[64],a,bb,c,d,e,f,g,h,t1,t2;
    for(int i=0;i<16;++i) w[i]=(static_cast<uint32_t>(b[i*4])<<24)|(static_cast<uint32_t>(b[i*4+1])<<16)|(static_cast<uint32_t>(b[i*4+2])<<8)|static_cast<uint32_t>(b[i*4+3]);
    for(int i=16;i<64;++i) w[i]=A3s1(w[i-2])+w[i-7]+A3s0(w[i-15])+w[i-16];
    a=s[0];bb=s[1];c=s[2];d=s[3];e=s[4];f=s[5];g=s[6];h=s[7];
    for(int i=0;i<64;++i){t1=h+A3S1(e)+A3CH(e,f,g)+K3[i]+w[i];t2=A3S0(a)+A3MAJ(a,bb,c);h=g;g=f;f=e;e=d+t1;d=c;c=bb;bb=a;a=t1+t2;}
    s[0]+=a;s[1]+=bb;s[2]+=c;s[3]+=d;s[4]+=e;s[5]+=f;s[6]+=g;s[7]+=h;
}
static std::string sha256_file(const fs::path& p) {
    SHA256Ctx3 ctx;
    ctx.state[0]=0x6a09e667;ctx.state[1]=0xbb67ae85;ctx.state[2]=0x3c6ef372;ctx.state[3]=0xa54ff53a;
    ctx.state[4]=0x510e527f;ctx.state[5]=0x9b05688c;ctx.state[6]=0x1f83d9ab;ctx.state[7]=0x5be0cd19;
    ctx.count=0;ctx.buflen=0;
    std::ifstream f(p, std::ios::binary);
    uint8_t tmp2[4096];
    while (f) {
        f.read(reinterpret_cast<char*>(tmp2), sizeof(tmp2)); // fusa:unsafe SHA-256 FIPS 180-4 binary read
        auto n = static_cast<size_t>(f.gcount());
        for (size_t i=0;i<n;++i){ctx.buf[ctx.buflen++]=tmp2[i];if(ctx.buflen==64){a3_transform(ctx.state,ctx.buf);ctx.count+=512;ctx.buflen=0;}}
    }
    ctx.count+=ctx.buflen*8;ctx.buf[ctx.buflen++]=0x80;
    if(ctx.buflen>56){while(ctx.buflen<64)ctx.buf[ctx.buflen++]=0;a3_transform(ctx.state,ctx.buf);ctx.buflen=0;}
    while(ctx.buflen<56)ctx.buf[ctx.buflen++]=0;
    for(int i=7;i>=0;--i)ctx.buf[ctx.buflen++]=(ctx.count>>(i*8))&0xff;
    a3_transform(ctx.state,ctx.buf);
    uint8_t dig[32];
    for(int i=0;i<8;++i){dig[i*4]=(ctx.state[i]>>24)&0xff;dig[i*4+1]=(ctx.state[i]>>16)&0xff;dig[i*4+2]=(ctx.state[i]>>8)&0xff;dig[i*4+3]=ctx.state[i]&0xff;}
    static const char HEX[]="0123456789abcdef";
    std::string out(64,'0');
    for(int i=0;i<32;++i){out[i*2]=HEX[(dig[i]>>4)&0xf];out[i*2+1]=HEX[dig[i]&0xf];}
    return out;
}

} // namespace

//fusa:req REQ-AUDIT001 REQ-AUDIT002 REQ-AUDIT003 REQ-AUDIT004
Result<AuditManifest> pack(const fs::path& project_root, const fs::path& output_path_in) {
    // A relative `output_path` (the common case: --dir "." with no --output,
    // e.g. `cpfusa audit-pack --dir .`) must be resolved against the
    // *current* working directory up front. Below, the two `zip` invocations
    // `cd` into two different directories (project_root, then the system
    // temp dir) — embedding a still-relative output_path verbatim into both
    // silently resolves it against two different locations, so the second
    // command (adding manifest.json) creates/updates a stray file in the
    // temp dir instead of the real target, while fs::exists(output_path)
    // below still reports success because the *first* zip (without the
    // manifest) really did land at the right place.
    fs::path output_path = fs::absolute(output_path_in);

    AuditManifest manifest;
    manifest.format       = "cpp-FuSa Audit Pack v1";
    manifest.generated_at = now_iso8601();
    manifest.project      = project_root.filename().string();

    // Collect present evidence files and compute SHA-256. §8 MUST: every
    // §1.2 input file and §1.3 generated file present at the project root
    // (including the open-ended `<standard>-gap-report.json` family) — not
    // just a hardcoded subset.
    struct FileInfo { std::string name; std::string sha256; long long size; };
    std::vector<FileInfo> present;
    for (const auto& name : release::list_present_evidence_files(project_root)) {
        auto p = project_root / name;
        present.push_back({name, sha256_file(p), static_cast<long long>(fs::file_size(p))});
        manifest.files.push_back({name, present.back().sha256, present.back().size});
    }

    // Write manifest.json (§8: lowercase, at ZIP root) to a temp file, then zip everything.
    auto tmp_manifest = fs::temp_directory_path() / "manifest.json";
    {
        json j;
        // §3.1 common header on the audit manifest
        j["schemaVersion"] = std::string(SpecVersion);
        j["kind"]          = "audit-manifest";
        j["tool"]          = "cpp-FuSa";
        j["toolVersion"]   = std::string(Version);
        j["language"]      = "cpp";
        j["generatedAt"]   = manifest.generated_at;
        j["module"]        = "github.com/SoundMatt/cpp-FuSa";
        json fa = json::array();
        for (const auto& f : present)
            fa.push_back({{"path", f.name}, {"size", f.size},
                          {"sha256", f.sha256}});  // §2.7: bare hex for sha256-named field
        j["files"] = fa;
        std::ofstream mf(tmp_manifest);
        mf << j.dump(2) << "\n";
    }

    // Build zip using system zip command.
    // Remove existing archive to avoid appending.
    if (fs::exists(output_path)) fs::remove(output_path);

    // Collect files to zip from project_root + the manifest.
    std::vector<std::string> present_names;
    for (const auto& info : present) {
        present_names.push_back(info.name);
    }

    // When there are no evidence files present, skip this step entirely —
    // `zip` with no file operands exits non-zero ("Nothing to do!") even
    // though that's not a failure; the archive still gets created below
    // when manifest.json is added.
    if (!present.empty()) {
        std::vector<std::string> zip_args = {"zip", "-q", output_path.string()};
        zip_args.insert(zip_args.end(), present_names.begin(), present_names.end());
        auto zip_res = run_argv_cwd(project_root.string(), zip_args);
        if (zip_res.exit_code != 0) {
            // The system `zip` binary is missing (or failed) — do not fall
            // back to writing a non-ZIP artefact under the requested name
            // while claiming success. Fail loudly instead (spec §8 MUST).
            return std::string("failed to create ZIP archive (is 'zip' installed?): ")
                 + (zip_res.output.empty() ? "zip command failed" : trim_trailing(zip_res.output));
        }
    }

    // Add manifest.json (from tmp) into the zip at the root.
    auto manifest_res = run_argv_cwd(
        fs::temp_directory_path().string(),
        {"zip", "-q", output_path.string(), "manifest.json"});
    if (manifest_res.exit_code != 0) {
        return std::string("failed to add manifest.json to ZIP archive: ")
             + (manifest_res.output.empty() ? "zip command failed" : trim_trailing(manifest_res.output));
    }

    if (!fs::exists(output_path)) {
        return std::string("zip reported success but did not produce an output archive at ")
             + output_path.string();
    }

    return manifest;
}

} // namespace cpfusa::auditpack
