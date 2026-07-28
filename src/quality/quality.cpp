#include "quality.hpp"
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <map>
#include <regex>
#include <set>
#include <sstream>

namespace cpfusa::quality {

using json = nlohmann::json;

namespace {

// ---- minimal SHA-256 (FIPS PUB 180-4) --------------------------------------
// Self-contained, matching this codebase's existing convention (sign.cpp,
// qualify.cpp, sci.cpp, release.cpp, auditpack.cpp each inline their own).

struct Sha256Ctx {
    uint32_t state[8];
    uint64_t count;
    uint8_t  buf[64];
    uint32_t buflen;
};

const uint32_t kK[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define QROTR(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define QCH(x,y,z)  (((x)&(y))^(~(x)&(z)))
#define QMAJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
#define QS0(x) (QROTR(x,2)^QROTR(x,13)^QROTR(x,22))
#define QS1(x) (QROTR(x,6)^QROTR(x,11)^QROTR(x,25))
#define Qs0(x) (QROTR(x,7)^QROTR(x,18)^((x)>>3))
#define Qs1(x) (QROTR(x,17)^QROTR(x,19)^((x)>>10))

void sha256_transform(uint32_t s[8], const uint8_t b[64]) {
    uint32_t w[64], a, bb, c, d, e, f, g, h, t1, t2;
    for (int i = 0; i < 16; ++i)
        w[i] = (static_cast<uint32_t>(b[i*4]) << 24) | (static_cast<uint32_t>(b[i*4+1]) << 16) |
               (static_cast<uint32_t>(b[i*4+2]) << 8) | static_cast<uint32_t>(b[i*4+3]);
    for (int i = 16; i < 64; ++i) w[i] = Qs1(w[i-2]) + w[i-7] + Qs0(w[i-15]) + w[i-16];
    a=s[0]; bb=s[1]; c=s[2]; d=s[3]; e=s[4]; f=s[5]; g=s[6]; h=s[7];
    for (int i = 0; i < 64; ++i) {
        t1 = h + QS1(e) + QCH(e,f,g) + kK[i] + w[i];
        t2 = QS0(a) + QMAJ(a,bb,c);
        h=g; g=f; f=e; e=d+t1; d=c; c=bb; bb=a; a=t1+t2;
    }
    s[0]+=a; s[1]+=bb; s[2]+=c; s[3]+=d; s[4]+=e; s[5]+=f; s[6]+=g; s[7]+=h;
}

void sha256_init(Sha256Ctx& ctx) {
    ctx.state[0]=0x6a09e667; ctx.state[1]=0xbb67ae85;
    ctx.state[2]=0x3c6ef372; ctx.state[3]=0xa54ff53a;
    ctx.state[4]=0x510e527f; ctx.state[5]=0x9b05688c;
    ctx.state[6]=0x1f83d9ab; ctx.state[7]=0x5be0cd19;
    ctx.count=0; ctx.buflen=0;
}

void sha256_update(Sha256Ctx& ctx, const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        ctx.buf[ctx.buflen++] = data[i]; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
        if (ctx.buflen == 64) {
            sha256_transform(ctx.state, ctx.buf);
            ctx.count += 512;
            ctx.buflen = 0;
        }
    }
}

void sha256_final(Sha256Ctx& ctx, uint8_t digest[32]) {
    ctx.count += ctx.buflen * 8;
    ctx.buf[ctx.buflen++] = 0x80;
    if (ctx.buflen > 56) {
        while (ctx.buflen < 64) ctx.buf[ctx.buflen++] = 0;
        sha256_transform(ctx.state, ctx.buf);
        ctx.buflen = 0;
    }
    while (ctx.buflen < 56) ctx.buf[ctx.buflen++] = 0;
    for (int i = 7; i >= 0; --i) ctx.buf[ctx.buflen++] = static_cast<uint8_t>((ctx.count >> (i * 8)) & 0xff);
    sha256_transform(ctx.state, ctx.buf);
    for (int i = 0; i < 8; ++i) {
        digest[i*4]   = (ctx.state[i] >> 24) & 0xff;
        digest[i*4+1] = (ctx.state[i] >> 16) & 0xff;
        digest[i*4+2] = (ctx.state[i] >> 8)  & 0xff;
        digest[i*4+3] =  ctx.state[i]        & 0xff;
    }
}

// ---- Rule A deny-list -------------------------------------------------------

// Bracket-wrapped instructional text, e.g. "[describe asset]" (§1.6.1 rule A).
const std::regex kBracketPlaceholder(R"(\[[A-Za-z][^\]]*\])");

std::string to_lower(const std::string& s) {
    std::string out = s;
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

bool contains_ci(const std::string& haystack_lower, const std::string& needle_lower) {
    return haystack_lower.find(needle_lower) != std::string::npos;
}

// §1.6.1 rule A deny-list substrings (checked case-insensitively).
const char* const kDenyListed[] = {
    "replace with", "example hazard", "tbd", "lorem ipsum", "fill in",
};

} // namespace

std::string sha256_hex(const std::string& data) {
    Sha256Ctx ctx;
    sha256_init(ctx);
    sha256_update(ctx, reinterpret_cast<const uint8_t*>(data.data()), data.size()); // fusa:unsafe SHA-256 std::string->uint8_t* for FIPS 180-4 input
    uint8_t digest[32];
    sha256_final(ctx, digest);
    static const char hex[] = "0123456789abcdef";
    std::string out(64, '0');
    for (int i = 0; i < 32; ++i) {
        out[i*2]   = hex[(digest[i] >> 4) & 0xf];
        out[i*2+1] = hex[digest[i] & 0xf];
    }
    return out;
}

std::string sha256_prefixed(const std::string& data) {
    return "sha256:" + sha256_hex(data);
}

namespace {

void write_canonical(std::ostringstream& out, const json& v) {
    switch (v.type()) {
        case json::value_t::null:
            out << "null";
            break;
        case json::value_t::boolean:
            out << (v.get<bool>() ? "true" : "false");
            break;
        case json::value_t::string:
            out << json(v.get<std::string>()).dump();
            break;
        case json::value_t::number_integer:
        case json::value_t::number_unsigned:
        case json::value_t::number_float:
            // nlohmann's own dump() already produces shortest round-trip
            // numeric formatting with no exponent for integers.
            out << v.dump();
            break;
        case json::value_t::array: {
            out << '[';
            bool first = true;
            for (const auto& e : v) {
                if (!first) out << ',';
                first = false;
                write_canonical(out, e);
            }
            out << ']';
            break;
        }
        case json::value_t::object: {
            std::vector<std::string> keys;
            keys.reserve(v.size());
            for (auto it = v.begin(); it != v.end(); ++it) keys.push_back(it.key());
            std::sort(keys.begin(), keys.end());
            out << '{';
            bool first = true;
            for (const auto& k : keys) {
                if (!first) out << ',';
                first = false;
                out << json(k).dump() << ':';
                write_canonical(out, v.at(k));
            }
            out << '}';
            break;
        }
        default:
            // binary/discarded values do not occur in these documents.
            break;
    }
}

} // namespace

std::string canonical_bytes(const json& j) {
    std::ostringstream out;
    write_canonical(out, j);
    return out.str();
}

std::string content_hash(const json& content) {
    return sha256_prefixed(canonical_bytes(content));
}

std::string fingerprint(const std::string& rule_id, const std::string& file,
                        const std::string& message) {
    // normalizedMessage: collapse ASCII digit runs to "#", collapse whitespace
    // runs to a single space, then trim (§4.2). Messages here are ASCII-only
    // tool-generated text, so NFC normalisation (only required for non-ASCII
    // input) is a no-op and intentionally omitted.
    std::string normalized;
    normalized.reserve(message.size());
    bool in_digits = false;
    bool in_space  = false;
    for (unsigned char c : message) {
        if (std::isdigit(c) != 0) {
            if (!in_digits) { normalized += '#'; in_digits = true; }
            in_space = false;
            continue;
        }
        in_digits = false;
        if (std::isspace(c) != 0) {
            if (!in_space) { normalized += ' '; in_space = true; }
            continue;
        }
        in_space = false;
        normalized += static_cast<char>(c);
    }
    // trim
    size_t start = normalized.find_first_not_of(' ');
    size_t end   = normalized.find_last_not_of(' ');
    if (start == std::string::npos) normalized.clear();
    else normalized = normalized.substr(start, end - start + 1);

    std::string canonical = rule_id + "\x1f" + file + "\x1f" + normalized;
    return sha256_prefixed(canonical);
}

Attestation parse(const json& doc) {
    Attestation a;
    if (!doc.is_object() || !doc.contains("attestation") || !doc["attestation"].is_object())
        return a; // fail-safe default: status "heuristic", present=false
    const auto& j = doc["attestation"];
    a.present               = true;
    a.status                = j.value("status", std::string("heuristic"));
    a.implementation_author = j.value("implementationAuthor", std::string());
    a.independent_reviewer  = j.value("independentReviewer", std::string());
    a.reviewed_at           = j.value("reviewedAt", std::string());
    a.content_hash          = j.value("contentHash", std::string());
    if (a.status != "reviewed") a.status = "heuristic"; // unrecognised => fail-safe
    return a;
}

json to_json(const Attestation& a) {
    json j;
    j["status"] = a.status;
    if (!a.implementation_author.empty()) j["implementationAuthor"] = a.implementation_author;
    if (a.status == "reviewed") {
        j["independentReviewer"] = a.independent_reviewer;
        j["reviewedAt"]          = a.reviewed_at;
        j["contentHash"]         = a.content_hash;
    }
    return j;
}

bool is_valid_reviewed(const Attestation& a, const json& content) {
    if (!a.present || a.status != "reviewed") return false;
    // Independence (MUST): a self-attestation does not satisfy "reviewed".
    if (a.independent_reviewer.empty()) return false;
    if (a.independent_reviewer == a.implementation_author) return false;
    // Hash pinning (MUST): stale content_hash => fall back to "heuristic".
    if (a.content_hash.empty()) return false;
    return a.content_hash == content_hash(content);
}

std::vector<Finding> scan_stub001(const std::vector<QualField>& fields,
                                  const std::string& artifact_file) {
    std::vector<Finding> out;
    for (const auto& f : fields) {
        std::string lower = to_lower(f.value);
        bool hit = std::regex_search(f.value, kBracketPlaceholder);
        if (!hit) {
            for (const char* needle : kDenyListed) {
                if (contains_ci(lower, needle)) { hit = true; break; }
            }
        }
        if (!hit) continue;
        std::string file = f.file.empty() ? artifact_file : f.file;
        std::string msg  = "field \"" + f.field + "\" contains placeholder/template text: \"" +
                            f.value + "\"";
        Finding finding(kStub001RuleId, Severity::ERROR, msg, file, f.line,
                        "Replace the placeholder with project-specific content, or waive via "
                        "disposition if this is a rare legitimate match.",
                        "safety");
        finding.fingerprint = fingerprint(kStub001RuleId, file, msg);
        out.push_back(std::move(finding));
    }
    return out;
}

std::vector<Finding> scan_stub002(const std::vector<QualField>& fields,
                                  const std::string& artifact_file) {
    std::vector<Finding> out;
    std::map<std::string, std::vector<const QualField*>> by_field;
    for (const auto& f : fields) by_field[f.field].push_back(&f);

    for (const auto& [field_name, entries] : by_field) {
        if (entries.size() < 10) continue; // rule B requires >=10 entries
        std::set<std::string> distinct;
        for (const auto* e : entries) distinct.insert(e->value);
        double ratio = static_cast<double>(distinct.size()) / static_cast<double>(entries.size());
        if (ratio >= 0.1) continue;

        char buf[160];
        std::snprintf(buf, sizeof(buf),
                      "field \"%s\" has a distinct-value ratio of %.2f across %zu entries "
                      "(< 0.10) — looks like one hardcoded string applied to every entry",
                      field_name.c_str(), ratio, entries.size());
        std::string msg = buf;
        Finding finding(kStub002RuleId, Severity::WARNING, msg, artifact_file, 0,
                        "Vary this field with the actual signature/behaviour of each entry, or "
                        "attest the content as independently reviewed (§1.6.2) if it is genuine.",
                        "safety");
        finding.fingerprint = fingerprint(kStub002RuleId, artifact_file, msg);
        out.push_back(std::move(finding));
    }
    return out;
}

} // namespace cpfusa::quality
