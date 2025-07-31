#include <windows.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/sha.h>
#include <iostream>
#include <iomanip>
#include <vector>
#include <random>
#include <chrono>
#include <thread>

constexpr size_t SYSTEM_ENTROPY_BYTES = 64;
constexpr int MIXING_ROUNDS           = 5;

// Obtain system entropy from Windows APIs or fallback mixing
bool get_system_entropy(std::vector<unsigned char>& buf, size_t length) {
    buf.resize(length);
    HCRYPTPROV hProv = 0;
    bool success = false;
    if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
        if (CryptGenRandom(hProv, (DWORD)length, buf.data()))
            success = true;
        CryptReleaseContext(hProv, 0);
    }
    if (!success) {
        std::random_device rd;
        std::mt19937_64 gen(rd());
        LARGE_INTEGER freq, counter;
        QueryPerformanceFrequency(&freq);
        for (size_t i = 0; i < length; ++i) {
            QueryPerformanceCounter(&counter);
            uint64_t e = counter.QuadPart ^ freq.QuadPart ^ gen();
            buf[i] = static_cast<unsigned char>(e & 0xFF);
            std::this_thread::sleep_for(std::chrono::microseconds(10));
        }
    }
    return true;
}

// Get entropy directly from OpenSSL's CSPRNG
bool get_openssl_entropy(std::vector<unsigned char>& buf, size_t length) {
    buf.resize(length);
    if (RAND_bytes(buf.data(), length) != 1) {
        buf.clear();
        return false;
    }
    return true;
}

// Mix entropy sources with iterative SHA-512
bool mix_entropy_sources(const std::vector<unsigned char>& sys,
                         const std::vector<unsigned char>& ossl,
                         std::vector<unsigned char>& mixed) {
    std::vector<unsigned char> combined = sys;
    combined.insert(combined.end(), ossl.begin(), ossl.end());
    SYSTEMTIME st; GetSystemTime(&st);
    combined.insert(combined.end(),
                    reinterpret_cast<unsigned char*>(&st),
                    reinterpret_cast<unsigned char*>(&st) + sizeof(st));
    LARGE_INTEGER freq, counter;
    if (QueryPerformanceFrequency(&freq) && QueryPerformanceCounter(&counter)) {
        combined.insert(combined.end(),
                        reinterpret_cast<unsigned char*>(&freq),
                        reinterpret_cast<unsigned char*>(&freq) + sizeof(freq));
        combined.insert(combined.end(),
                        reinterpret_cast<unsigned char*>(&counter),
                        reinterpret_cast<unsigned char*>(&counter) + sizeof(counter));
    }
    unsigned char hash[SHA512_DIGEST_LENGTH];
    SHA512_CTX ctx;
    SHA512_Init(&ctx);
    SHA512_Update(&ctx, combined.data(), combined.size());
    SHA512_Final(hash, &ctx);
    for (int i = 1; i < MIXING_ROUNDS; ++i) {
        SHA512_Init(&ctx);
        SHA512_Update(&ctx, hash, SHA512_DIGEST_LENGTH);
        SHA512_Final(hash, &ctx);
    }
    mixed.assign(hash, hash + SHA512_DIGEST_LENGTH);
    return true;
}

// Derive final key via HKDF-SHA512
bool hkdf_derive(const std::vector<unsigned char>& ikm,
                 std::vector<unsigned char>& out, int num_bytes) {
    const unsigned char salt[] = "enhanced-keygen-salt-v2";
    const unsigned char info[] = "mixed-entropy-key";
    out.resize(num_bytes);
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!pctx) return false;
    size_t outlen = num_bytes;
    bool ok = EVP_PKEY_derive_init(pctx) > 0
           && EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha512()) > 0
           && EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, sizeof(salt)-1) > 0
           && EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm.data(), ikm.size()) > 0
           && EVP_PKEY_CTX_add1_hkdf_info(pctx, info, sizeof(info)-1) > 0
           && EVP_PKEY_derive(pctx, out.data(), &outlen) > 0;
    EVP_PKEY_CTX_free(pctx);
    return ok && outlen == (size_t)num_bytes;
}

int main(int argc, char* argv[]) {
    int num_bytes = 32;
    if (argc > 1) {
        std::istringstream iss(argv[1]);
        iss >> num_bytes;
    }

    std::vector<unsigned char> sys, ossl, mixed, key;
    get_system_entropy(sys, SYSTEM_ENTROPY_BYTES);
    get_openssl_entropy(ossl, SYSTEM_ENTROPY_BYTES);
    mix_entropy_sources(sys, ossl, mixed);
    hkdf_derive(mixed, key, num_bytes);

    for (unsigned char b : key)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    std::cout << '\n';
    return 0;
}
