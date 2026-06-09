#include "sign.hpp"
#include <filesystem>
#include <fstream>
#include <random>
#include <cstdint>
#include <cstring>

namespace fs = std::filesystem;

namespace cpfusa::sign {

namespace {

// Minimal SHA-256 + HMAC-SHA256 implementation.
struct SHACtx {
    uint32_t state[8];
    uint64_t count;
    uint8_t  buf[64];
    uint32_t buflen;
};

static const uint32_t KS[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};
#define SROTR(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define SCH(x,y,z) (((x)&(y))^(~(x)&(z)))
#define SMAJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
#define SS0(x) (SROTR(x,2)^SROTR(x,13)^SROTR(x,22))
#define SS1(x) (SROTR(x,6)^SROTR(x,11)^SROTR(x,25))
#define Ss0(x) (SROTR(x,7)^SROTR(x,18)^((x)>>3))
#define Ss1(x) (SROTR(x,17)^SROTR(x,19)^((x)>>10))

static void sha_transform(uint32_t s[8], const uint8_t b[64]) {
    uint32_t w[64],a,bb,c,d,e,f,g,h,t1,t2;
    for(int i=0;i<16;++i) w[i]=(static_cast<uint32_t>(b[i*4])<<24)|(static_cast<uint32_t>(b[i*4+1])<<16)|(static_cast<uint32_t>(b[i*4+2])<<8)|static_cast<uint32_t>(b[i*4+3]);
    for(int i=16;i<64;++i) w[i]=Ss1(w[i-2])+w[i-7]+Ss0(w[i-15])+w[i-16];
    a=s[0];bb=s[1];c=s[2];d=s[3];e=s[4];f=s[5];g=s[6];h=s[7];
    for(int i=0;i<64;++i){t1=h+SS1(e)+SCH(e,f,g)+KS[i]+w[i];t2=SS0(a)+SMAJ(a,bb,c);h=g;g=f;f=e;e=d+t1;d=c;c=bb;bb=a;a=t1+t2;}
    s[0]+=a;s[1]+=bb;s[2]+=c;s[3]+=d;s[4]+=e;s[5]+=f;s[6]+=g;s[7]+=h;
}

static void sha_init(SHACtx& ctx) {
    ctx.state[0]=0x6a09e667;ctx.state[1]=0xbb67ae85;ctx.state[2]=0x3c6ef372;ctx.state[3]=0xa54ff53a;
    ctx.state[4]=0x510e527f;ctx.state[5]=0x9b05688c;ctx.state[6]=0x1f83d9ab;ctx.state[7]=0x5be0cd19;
    ctx.count=0;ctx.buflen=0;
}

static void sha_update(SHACtx& ctx, const uint8_t* data, size_t len) {
    for (size_t i=0;i<len;++i){
        ctx.buf[ctx.buflen++]=data[i];
        if(ctx.buflen==64){sha_transform(ctx.state,ctx.buf);ctx.count+=512;ctx.buflen=0;}
    }
}

static void sha_final(SHACtx& ctx, uint8_t digest[32]) {
    ctx.count+=ctx.buflen*8;ctx.buf[ctx.buflen++]=0x80;
    if(ctx.buflen>56){while(ctx.buflen<64)ctx.buf[ctx.buflen++]=0;sha_transform(ctx.state,ctx.buf);ctx.buflen=0;}
    while(ctx.buflen<56)ctx.buf[ctx.buflen++]=0;
    for(int i=7;i>=0;--i)ctx.buf[ctx.buflen++]=(ctx.count>>(i*8))&0xff;
    sha_transform(ctx.state,ctx.buf);
    for(int i=0;i<8;++i){digest[i*4]=(ctx.state[i]>>24)&0xff;digest[i*4+1]=(ctx.state[i]>>16)&0xff;digest[i*4+2]=(ctx.state[i]>>8)&0xff;digest[i*4+3]=ctx.state[i]&0xff;}
}

// HMAC-SHA256 of data with key.
static void hmac_sha256(const uint8_t* key, size_t key_len,
                        const uint8_t* data, size_t data_len,
                        uint8_t mac[32]) {
    uint8_t k_ipad[64]{}, k_opad[64]{};
    uint8_t k_prep[32];
    if (key_len <= 64) {
        std::memcpy(k_ipad, key, key_len);
        std::memcpy(k_opad, key, key_len);
    } else {
        SHACtx kh; sha_init(kh); sha_update(kh, key, key_len); sha_final(kh, k_prep);
        std::memcpy(k_ipad, k_prep, 32);
        std::memcpy(k_opad, k_prep, 32);
    }
    for (int i=0;i<64;++i){ k_ipad[i]^=0x36; k_opad[i]^=0x5c; }
    // inner hash
    uint8_t inner[32];
    { SHACtx h; sha_init(h); sha_update(h,k_ipad,64); sha_update(h,data,data_len); sha_final(h,inner); }
    // outer hash
    { SHACtx h; sha_init(h); sha_update(h,k_opad,64); sha_update(h,inner,32); sha_final(h,mac); }
}

std::string to_hex(const uint8_t* data, size_t n) {
    static const char HEX[] = "0123456789abcdef";
    std::string out(n*2,'0');
    for (size_t i=0;i<n;++i){out[i*2]=HEX[(data[i]>>4)&0xf];out[i*2+1]=HEX[data[i]&0xf];}
    return out;
}

bool from_hex(const std::string& s, uint8_t* out, size_t n) {
    if (s.size() != n*2) return false;
    for (size_t i=0;i<n;++i) {
        auto h = [](char c) -> int {
            if (c>='0'&&c<='9') return c-'0';
            if (c>='a'&&c<='f') return c-'a'+10;
            if (c>='A'&&c<='F') return c-'A'+10;
            return -1;
        };
        int hi = h(s[i*2]), lo = h(s[i*2+1]);
        if (hi<0||lo<0) return false;
        out[i] = static_cast<uint8_t>((hi<<4)|lo);
    }
    return true;
}

// Returns "" on error and sets err_out. Returns 64-char hex on success.
std::string load_key_hex(const fs::path& key_path, std::string& err_out) {
    if (!fs::exists(key_path)) {
        err_out = "sign: key file not found: " + key_path.string();
        return {};
    }
    std::ifstream f(key_path);
    std::string hex; f >> hex;
    if (hex.size() != 64) {
        err_out = "sign: key must be 64 hex characters (32 bytes)";
        return {};
    }
    return hex;
}

// HMAC-SHA256 of a file.
std::string hmac_file(const fs::path& target, const uint8_t key[32]) {
    SHACtx h; sha_init(h);
    std::ifstream f(target, std::ios::binary);
    uint8_t buf[4096];
    while (f) {
        f.read(reinterpret_cast<char*>(buf), sizeof(buf)); // fusa:unsafe SHA-256 FIPS 180-4 binary read
        auto n = static_cast<size_t>(f.gcount());
        sha_update(h, buf, n);
    }
    uint8_t file_digest[32]; sha_final(h, file_digest);
    uint8_t mac[32];
    hmac_sha256(key, 32, file_digest, 32, mac);
    return to_hex(mac, 32);
}

} // namespace

//fusa:req REQ-SIGN001
Result<std::monostate> keygen(const fs::path& key_path) {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dist;
    uint8_t key[32];
    for (int i = 0; i < 4; ++i) {
        uint64_t v = dist(gen);
        std::memcpy(key + i*8, &v, 8);
    }
    std::string hex = to_hex(key, 32) + "\n";
    try {
        std::ofstream out(key_path);
        out << hex;
    } catch (const std::exception& e) {
        return std::string("sign: keygen write: ") + e.what();
    }
    return std::monostate{};
}

//fusa:req REQ-SIGN002
Result<std::monostate> sign_file(const fs::path& target, const fs::path& key_path) {
    if (!fs::exists(target))
        return std::string("sign: target not found: ") + target.string();
    std::string err;
    auto hex = load_key_hex(key_path, err);
    if (!err.empty()) return err;
    uint8_t key[32];
    if (!from_hex(hex, key, 32))
        return std::string("sign: invalid key hex");
    auto mac = hmac_file(target, key);
    auto sig_path = fs::path(target.string() + ".sig");
    try {
        std::ofstream out(sig_path);
        out << mac << "\n";
    } catch (const std::exception& e) {
        return std::string("sign: write sig: ") + e.what();
    }
    return std::monostate{};
}

//fusa:req REQ-SIGN003 REQ-SIGN004 REQ-SIGN005
Result<bool> verify_file(const fs::path& target, const fs::path& key_path) {
    if (!fs::exists(target))
        return std::string("sign: target not found: ") + target.string();
    auto sig_path = fs::path(target.string() + ".sig");
    if (!fs::exists(sig_path))
        return std::string("sign: signature file not found: ") + sig_path.string();
    std::string err;
    auto hex = load_key_hex(key_path, err);
    if (!err.empty()) return err;
    uint8_t key[32];
    if (!from_hex(hex, key, 32))
        return std::string("sign: invalid key hex");
    auto expected = hmac_file(target, key);
    std::ifstream sf(sig_path); std::string stored; sf >> stored;
    // Constant-time compare to avoid timing attacks.
    if (stored.size() != expected.size()) return false;
    uint8_t diff = 0;
    for (size_t i = 0; i < stored.size(); ++i)
        diff |= static_cast<uint8_t>(stored[i] ^ expected[i]);
    return diff == 0;
}

} // namespace cpfusa::sign
