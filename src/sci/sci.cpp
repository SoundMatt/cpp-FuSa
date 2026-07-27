#include "sci.hpp"
#include <chrono>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <nlohmann/json.hpp>

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace cpfusa::sci {

namespace {
std::string now_iso() {
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    std::ostringstream ss;
    ss << std::put_time(std::gmtime(&t), "%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}

// Minimal SHA-256 for file hashing
//fusa:req REQ-SCI002
constexpr uint32_t SCI_K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define SCI_ROR(v,n) (((v) >> (n)) | ((v) << (32-(n))))
#define SCI_CH(e,f,g) (((e) & (f)) ^ (~(e) & (g)))
#define SCI_MAJ(a,b,c) (((a) & (b)) ^ ((a) & (c)) ^ ((b) & (c)))
#define SCI_EP0(a) (SCI_ROR(a,2) ^ SCI_ROR(a,13) ^ SCI_ROR(a,22))
#define SCI_EP1(e) (SCI_ROR(e,6) ^ SCI_ROR(e,11) ^ SCI_ROR(e,25))
#define SCI_SIG0(x) (SCI_ROR(x,7) ^ SCI_ROR(x,18) ^ ((x) >> 3))
#define SCI_SIG1(x) (SCI_ROR(x,17) ^ SCI_ROR(x,19) ^ ((x) >> 10))

std::string sha256_file(const fs::path& p) {
    std::ifstream f(p, std::ios::binary);
    if (!f) return "";
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(f)),
                               std::istreambuf_iterator<char>());
    uint32_t h0=0x6a09e667,h1=0xbb67ae85,h2=0x3c6ef372,h3=0xa54ff53a;
    uint32_t h4=0x510e527f,h5=0x9b05688c,h6=0x1f83d9ab,h7=0x5be0cd19;
    uint64_t bit_len = static_cast<uint64_t>(data.size()) * 8;
    data.push_back(0x80);
    while (data.size() % 64 != 56) data.push_back(0x00);
    for (int i = 7; i >= 0; --i) data.push_back(static_cast<uint8_t>(bit_len >> (i*8)));
    for (size_t i = 0; i < data.size(); i += 64) {
        uint32_t w[64]{};
        for (int j = 0; j < 16; ++j)
            w[j] = (uint32_t(data[i+j*4])<<24)|(uint32_t(data[i+j*4+1])<<16)|
                   (uint32_t(data[i+j*4+2])<<8)|uint32_t(data[i+j*4+3]);
        for (int j = 16; j < 64; ++j)
            w[j] = SCI_SIG1(w[j-2]) + w[j-7] + SCI_SIG0(w[j-15]) + w[j-16];
        uint32_t a=h0,b=h1,c=h2,d=h3,e=h4,f2=h5,g=h6,hh=h7;
        for (int j = 0; j < 64; ++j) {
            uint32_t t1 = hh + SCI_EP1(e) + SCI_CH(e,f2,g) + SCI_K[j] + w[j];
            uint32_t t2 = SCI_EP0(a) + SCI_MAJ(a,b,c);
            hh=g; g=f2; f2=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
        }
        h0+=a; h1+=b; h2+=c; h3+=d; h4+=e; h5+=f2; h6+=g; h7+=hh;
    }
    char buf[65];
    std::snprintf(buf, sizeof(buf), "%08x%08x%08x%08x%08x%08x%08x%08x", // NOLINT
                  h0,h1,h2,h3,h4,h5,h6,h7);
    return buf;
}

struct ArtifactDef { std::string category; std::string artifact; };
std::vector<ArtifactDef> lifecycle_items() {
    return {
        {"Requirements",       ".fusa-reqs.json"},
        {"Configuration",      ".fusa.json"},
        {"Test Evidence",      ".fusa-evidence.json"},
        {"Analysis",           "check-report.json"},
        {"Analysis",           "cyber-report.json"},
        {"Safety",             "fmea.json"},
        {"Safety",             "tara.json"},
        {"Safety",             "safety-case.json"},
        {"Qualification",      "qualify-report.json"},
        {"Release",            "sbom.json"},
        {"Release",            "provenance.json"},
        {"Release",            "artifact-manifest.json"},
        {"Audit",              "audit-pack.zip"},
        {"Gap Analysis",       "iso26262-gap-report.json"},
        {"Gap Analysis",       "iec61508-gap-report.json"},
        {"Gap Analysis",       "do178-gap-report.json"},
        {"Summary",            "sas.json"},
    };
}
} // anonymous namespace

//fusa:req REQ-SCI001 REQ-SCI002
SCI build(const fs::path& dir, const std::string& project, const std::string& version) {
    SCI s;
    s.project = project;
    s.version = version;
    s.generated_at = now_iso();

    for (auto& def : lifecycle_items()) {
        LifecycleItem item;
        item.category = def.category;
        item.artifact = def.artifact;
        item.path = (dir / def.artifact).string();
        item.present = fs::exists(dir / def.artifact);
        if (item.present) item.sha256 = sha256_file(dir / def.artifact);
        s.items.push_back(item);
    }
    return s;
}

void write_json(const fs::path& out, const SCI& s) {
    json j;
    j["generatedAt"] = s.generated_at;
    j["project"]     = s.project;
    j["version"]     = s.version;
    j["items"]       = json::array();
    for (auto& item : s.items) {
        j["items"].push_back({
            {"category", item.category},
            {"artifact", item.artifact},
            {"present",  item.present},
            {"sha256",   item.sha256}
        });
    }
    std::ofstream f(out);
    f << j.dump(2);
}

} // namespace cpfusa::sci
