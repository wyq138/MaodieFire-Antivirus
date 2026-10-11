// FireAntivirus.CPP - SHA256 实现
// 纯 C++17,无任何外部依赖
#include "FireAntivirus/Helper.h"
#include <cstring>
#include <array>

namespace FireAntivirus {
namespace Helper {

namespace {

class Sha256 {
public:
    Sha256() { Reset(); }

    void Reset() {
        state_ = {
            0x6a09e667UL, 0xbb67ae85UL, 0x3c6ef372UL, 0xa54ff53aUL,
            0x510e527fUL, 0x9b05688cUL, 0x1f83d9abUL, 0x5be0cd19UL
        };
        bit_len_ = 0;
        buffer_size_ = 0;
    }

    void Update(const uint8_t* data, size_t len) {
        while (len > 0) {
            size_t take = std::min(len, (size_t)(64 - buffer_size_));
            std::memcpy(buffer_ + buffer_size_, data, take);
            buffer_size_ += take;
            data += take;
            len  -= take;
            if (buffer_size_ == 64) {
                Transform(buffer_);
                bit_len_ += 512;
                buffer_size_ = 0;
            }
        }
    }

    std::array<uint8_t, 32> Finalize() {
        std::array<uint8_t, 32> out;
        uint64_t total_bits = bit_len_ + (uint64_t)buffer_size_ * 8;

        // 添加 0x80
        buffer_[buffer_size_++] = 0x80;

        if (buffer_size_ > 56) {
            while (buffer_size_ < 64) buffer_[buffer_size_++] = 0;
            Transform(buffer_);
            buffer_size_ = 0;
        }
        while (buffer_size_ < 56) buffer_[buffer_size_++] = 0;

        // 64-bit BE length
        for (int i = 7; i >= 0; --i) {
            buffer_[buffer_size_++] = (uint8_t)((total_bits >> (i * 8)) & 0xFF);
        }
        Transform(buffer_);

        for (int i = 0; i < 8; ++i) {
            out[i * 4 + 0] = (uint8_t)((state_[i] >> 24) & 0xFF);
            out[i * 4 + 1] = (uint8_t)((state_[i] >> 16) & 0xFF);
            out[i * 4 + 2] = (uint8_t)((state_[i] >> 8) & 0xFF);
            out[i * 4 + 3] = (uint8_t)(state_[i] & 0xFF);
        }
        return out;
    }

private:
    static uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

    static const uint32_t K[64];

    void Transform(const uint8_t* block) {
        uint32_t w[64];
        for (int i = 0; i < 16; ++i) {
            w[i] = ((uint32_t)block[i*4+0] << 24) |
                   ((uint32_t)block[i*4+1] << 16) |
                   ((uint32_t)block[i*4+2] << 8)  |
                   ((uint32_t)block[i*4+3]);
        }
        for (int i = 16; i < 64; ++i) {
            uint32_t s0 = rotr(w[i-15], 7) ^ rotr(w[i-15], 18) ^ (w[i-15] >> 3);
            uint32_t s1 = rotr(w[i-2], 17) ^ rotr(w[i-2], 19) ^ (w[i-2] >> 10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }

        uint32_t a = state_[0], b = state_[1], c = state_[2], d = state_[3];
        uint32_t e = state_[4], f = state_[5], g = state_[6], h = state_[7];

        for (int i = 0; i < 64; ++i) {
            uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t t1 = h + S1 + ch + K[i] + w[i];
            uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t t2 = S0 + mj;

            h = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }

        state_[0] += a; state_[1] += b; state_[2] += c; state_[3] += d;
        state_[4] += e; state_[5] += f; state_[6] += g; state_[7] += h;
    }

    std::array<uint32_t, 8> state_;
    uint8_t  buffer_[64]{};
    size_t   buffer_size_ = 0;
    uint64_t bit_len_ = 0;
};

const uint32_t Sha256::K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

} // anon

std::string ComputeBytesSha256(const uint8_t* data, size_t len) {
    Sha256 s;
    s.Update(data, len);
    auto hash = s.Finalize();
    std::string out;
    out.reserve(64);
    char buf[4];
    for (auto b : hash) {
        std::snprintf(buf, sizeof(buf), "%02x", b);
        out += buf;
    }
    return out;
}

std::string ComputeFileSha256(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return {};
    Sha256 s;
    constexpr size_t kBuf = 64 * 1024;
    std::vector<uint8_t> buf(kBuf);
    while (f) {
        f.read(reinterpret_cast<char*>(buf.data()), kBuf);
        std::streamsize got = f.gcount();
        if (got > 0) s.Update(buf.data(), static_cast<size_t>(got));
    }
    auto hash = s.Finalize();
    std::string out;
    out.reserve(64);
    char tmp[4];
    for (auto b : hash) {
        std::snprintf(tmp, sizeof(tmp), "%02x", b);
        out += tmp;
    }
    return out;
}

} // namespace Helper
} // namespace FireAntivirus
