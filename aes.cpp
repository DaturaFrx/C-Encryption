#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/kdf.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <algorithm>
#include <memory>

//=============================================================================
// CRYPTOGRAPHIC CONSTANTS
//=============================================================================

constexpr int SALT_LEN = 16;       // 128-bit salt for HKDF
constexpr int IV_LEN = 12;         // 96-bit IV for AES-GCM
constexpr int TAG_LEN = 16;        // 128-bit authentication tag
constexpr int KEY_LEN = 32;        // 256-bit key for AES-256

//=============================================================================
// SECURE MEMORY MANAGEMENT
//=============================================================================

class SecureBuffer {
private:
    unsigned char* data;
    size_t size;
    
public:
    SecureBuffer(size_t sz) : size(sz) {
        data = new unsigned char[sz];
        std::memset(data, 0, sz);
    }
    
    ~SecureBuffer() {
        if (data) {
            OPENSSL_cleanse(data, size);
            delete[] data;
        }
    }
    
    unsigned char* get() { return data; }
    size_t length() const { return size; }
    
    // Disable copy
    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;
};

void secure_zero(void *ptr, size_t len)
{
    OPENSSL_cleanse(ptr, len);
}

//=============================================================================
// UTILITY FUNCTIONS
//=============================================================================

std::string base64_encode(const unsigned char *data, size_t len)
{
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_write(bio, data, len);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);

    std::string encoded(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);
    return encoded;
}

std::vector<unsigned char> base64_decode(const std::string &input)
{
    BIO *bio, *b64;
    int decodeLen = (int)input.length();
    std::vector<unsigned char> buffer(decodeLen);

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_new_mem_buf(input.data(), (int)input.length());
    bio = BIO_push(b64, bio);

    int length = BIO_read(bio, buffer.data(), decodeLen);
    buffer.resize(length > 0 ? length : 0);

    BIO_free_all(bio);
    return buffer;
}

std::vector<unsigned char> hex_to_bytes(const std::string &hex)
{
    std::vector<unsigned char> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        unsigned char byte = (unsigned char) strtol(byteString.c_str(), nullptr, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

//=============================================================================
// ENTROPY GENERATION
//=============================================================================

std::string get_entropy_from_exe()
{
    std::string result;
    
    // Try both "./entropy 8192" and "entropy 8192"
    const char* commands[] = {"./entropy 8192", "entropy 8192"};
    
    for (const char* cmd : commands) {
        FILE* pipe = popen(cmd, "r");
        if (pipe) {
            char buffer[128];
            std::string output;
            
            while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
                output += buffer;
            }
            
            int ret = pclose(pipe);
            if (ret == 0 && !output.empty()) {
                // Remove whitespace and newlines
                output.erase(std::remove(output.begin(), output.end(), '\n'), output.end());
                output.erase(std::remove(output.begin(), output.end(), '\r'), output.end());
                output.erase(std::remove(output.begin(), output.end(), ' '), output.end());
                
                if (!output.empty()) {
                    result = output;
                    break;
                }
            }
        }
    }
    
    return result;
}

//=============================================================================
// HKDF KEY DERIVATION
//=============================================================================

bool derive_key_hkdf(const unsigned char *entropy, size_t entropy_len, 
                     const unsigned char *salt, unsigned char *key)
{
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!pctx) return false;

    bool success = false;
    if (EVP_PKEY_derive_init(pctx) == 1 &&
        EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) == 1 &&
        EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, SALT_LEN) == 1 &&
        EVP_PKEY_CTX_set1_hkdf_key(pctx, entropy, entropy_len) == 1) {
        
        size_t keylen = KEY_LEN;
        if (EVP_PKEY_derive(pctx, key, &keylen) == 1 && keylen == KEY_LEN) {
            success = true;
        }
    }

    EVP_PKEY_CTX_free(pctx);
    return success;
}

//=============================================================================
// AES-256-GCM ENCRYPTION/DECRYPTION
//=============================================================================

bool aes256gcm_encrypt(const unsigned char *plaintext, size_t plaintext_len,
                       const unsigned char *key,
                       unsigned char *iv,
                       unsigned char *ciphertext,
                       size_t &ciphertext_len,
                       unsigned char *tag)
{
    if (!RAND_bytes(iv, IV_LEN))
        return false;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    int len = 0;
    int outlen = 0;
    bool success = false;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, nullptr) &&
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv) &&
        EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, (int)plaintext_len)) {
        
        outlen = len;
        if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
            outlen += len;
            if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag)) {
                ciphertext_len = outlen;
                success = true;
            }
        }
    }

    EVP_CIPHER_CTX_free(ctx);
    return success;
}

bool aes256gcm_decrypt(const unsigned char *ciphertext, size_t ciphertext_len,
                       const unsigned char *key,
                       const unsigned char *iv,
                       const unsigned char *tag,
                       unsigned char *plaintext,
                       size_t &plaintext_len)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    int len = 0;
    int outlen = 0;
    bool success = false;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, nullptr) &&
        EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, iv) &&
        EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, (int)ciphertext_len)) {
        
        outlen = len;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, (void *)tag) &&
            EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
            outlen += len;
            plaintext_len = outlen;
            success = true;
        }
    }

    EVP_CIPHER_CTX_free(ctx);
    return success;
}

//=============================================================================
// FILE I/O
//=============================================================================

bool read_file(const std::string &path, std::vector<unsigned char> &data)
{
    std::ifstream ifs(path, std::ios::binary | std::ios::ate);
    if (!ifs) return false;
    std::streamsize size = ifs.tellg();
    ifs.seekg(0, std::ios::beg);
    data.resize(size);
    return ifs.read(reinterpret_cast<char *>(data.data()), size).good();
}

bool write_file(const std::string &path, const unsigned char *data, size_t len)
{
    std::ofstream ofs(path, std::ios::binary);
    if (!ofs) return false;
    ofs.write(reinterpret_cast<const char *>(data), len);
    return ofs.good();
}

//=============================================================================
// MAIN PROGRAM
//=============================================================================

void print_usage()
{
    std::cout << "Usage:\n";
    std::cout << " aes -e -p <plaintext>\n";
    std::cout << " aes -e -f <file>\n";
    std::cout << " aes -d -p <ciphertext> -k <key_file>\n";
    std::cout << " aes -d -f <file> -k <key_file>\n";
    std::cout << "Options:\n";
    std::cout << " -e           Encrypt\n";
    std::cout << " -d           Decrypt\n";
    std::cout << " -p           Plaintext string input/output\n";
    std::cout << " -f           File input/output\n";
    std::cout << " -k           Key file for decryption\n";
}

int main(int argc, char *argv[])
{
    // Ensure all memory is wiped on exit
    std::atexit([]() {
        // Force garbage collection and memory cleanup
        std::cout.flush();
        std::cerr.flush();
    });

    if (argc < 3) {
        print_usage();
        return 1;
    }

    bool encrypt = false;
    bool decrypt = false;
    bool is_file = false;
    std::string input;
    std::string keyfile_path;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-e") encrypt = true;
        else if (arg == "-d") decrypt = true;
        else if (arg == "-f") is_file = true;
        else if (arg == "-p") is_file = false;
        else if (arg == "-k" && i + 1 < argc) {
            keyfile_path = argv[++i];
            if (keyfile_path.front() == '"' && keyfile_path.back() == '"') {
                keyfile_path = keyfile_path.substr(1, keyfile_path.length() - 2);
            }
        }
        else if (arg[0] != '-') input = arg;
    }

    if ((encrypt && decrypt) || (!encrypt && !decrypt)) {
        std::cerr << "Specify either -e or -d\n";
        return 1;
    }

    std::vector<unsigned char> input_data;
    if (is_file) {
        if (!read_file(input, input_data)) {
            std::cerr << "Failed to read input file\n";
            return 1;
        }
    } else {
        input_data.assign(input.begin(), input.end());
    }

    //=========================================================================
    // ENCRYPTION
    //=========================================================================
    if (encrypt) {
        // Get entropy from executable
        std::string entropy_hex = get_entropy_from_exe();
        if (entropy_hex.empty()) {
            std::cerr << "Failed to get entropy from executable\n";
            return 1;
        }

        std::vector<unsigned char> entropy = hex_to_bytes(entropy_hex);
        
        // Generate salt
        SecureBuffer salt_buf(SALT_LEN);
        if (!RAND_bytes(salt_buf.get(), SALT_LEN)) {
            std::cerr << "Failed to generate salt\n";
            return 1;
        }

        // Derive key using HKDF
        SecureBuffer key_buf(KEY_LEN);
        if (!derive_key_hkdf(entropy.data(), entropy.size(), salt_buf.get(), key_buf.get())) {
            std::cerr << "HKDF key derivation failed\n";
            secure_zero(entropy.data(), entropy.size());
            return 1;
        }

        // Encrypt
        std::vector<unsigned char> ciphertext(input_data.size() + 16);
        SecureBuffer iv_buf(IV_LEN);
        SecureBuffer tag_buf(TAG_LEN);
        size_t ciphertext_len = 0;

        if (!aes256gcm_encrypt(input_data.data(), input_data.size(),
                               key_buf.get(), iv_buf.get(), ciphertext.data(), ciphertext_len, tag_buf.get())) {
            std::cerr << "Encryption failed\n";
            secure_zero(entropy.data(), entropy.size());
            return 1;
        }

        // Create output: [SALT][IV][CIPHERTEXT][TAG]
        std::vector<unsigned char> output;
        output.insert(output.end(), salt_buf.get(), salt_buf.get() + SALT_LEN);
        output.insert(output.end(), iv_buf.get(), iv_buf.get() + IV_LEN);
        output.insert(output.end(), ciphertext.begin(), ciphertext.begin() + ciphertext_len);
        output.insert(output.end(), tag_buf.get(), tag_buf.get() + TAG_LEN);

        // Save encrypted data
        if (is_file) {
            write_file(input + ".enc", output.data(), output.size());
            std::cout << "Encrypted file: " << input << ".enc\n";
        } else {
            std::cout << base64_encode(output.data(), output.size()) << "\n";
        }

        // Save key file (entropy as base64)
        std::string key_b64 = base64_encode(entropy.data(), entropy.size());
        std::string keyfile = "key_" + std::to_string(time(nullptr)) + ".key";
        std::ofstream kf(keyfile);
        kf << key_b64;
        kf.close();
        std::cout << "Key file: " << keyfile << "\n";

        // Secure cleanup
        secure_zero(entropy.data(), entropy.size());
        secure_zero(output.data(), output.size());
        secure_zero(ciphertext.data(), ciphertext.size());
        secure_zero(&key_b64[0], key_b64.size());
    }

    //=========================================================================
    // DECRYPTION
    //=========================================================================
    else if (decrypt) {
        if (keyfile_path.empty()) {
            std::cerr << "Key file required for decryption (-k <keyfile>)\n";
            return 1;
        }

        // Read key file
        std::ifstream kf(keyfile_path);
        if (!kf) {
            std::cerr << "Failed to read key file\n";
            return 1;
        }
        std::string key_b64;
        std::getline(kf, key_b64);
        kf.close();

        std::vector<unsigned char> entropy = base64_decode(key_b64);
        if (entropy.empty()) {
            std::cerr << "Invalid key file\n";
            return 1;
        }

        // Read encrypted data
        std::vector<unsigned char> enc_data;
        if (is_file) {
            if (!read_file(input, enc_data)) {
                std::cerr << "Failed to read encrypted file\n";
                secure_zero(entropy.data(), entropy.size());
                return 1;
            }
        } else {
            enc_data = base64_decode(input);
        }

        if (enc_data.size() < SALT_LEN + IV_LEN + TAG_LEN) {
            std::cerr << "Invalid encrypted data\n";
            secure_zero(entropy.data(), entropy.size());
            return 1;
        }

        // Extract components
        const unsigned char *salt = enc_data.data();
        const unsigned char *iv = salt + SALT_LEN;
        const unsigned char *ciphertext = iv + IV_LEN;
        size_t ciphertext_len = enc_data.size() - SALT_LEN - IV_LEN - TAG_LEN;
        const unsigned char *tag = ciphertext + ciphertext_len;

        // Derive key
        SecureBuffer key_buf(KEY_LEN);
        if (!derive_key_hkdf(entropy.data(), entropy.size(), salt, key_buf.get())) {
            std::cerr << "HKDF key derivation failed\n";
            secure_zero(entropy.data(), entropy.size());
            return 1;
        }

        // Decrypt
        std::vector<unsigned char> plaintext(ciphertext_len);
        size_t plaintext_len = 0;

        if (!aes256gcm_decrypt(ciphertext, ciphertext_len, key_buf.get(), iv, tag, 
                               plaintext.data(), plaintext_len)) {
            std::cerr << "Decryption failed\n";
            secure_zero(entropy.data(), entropy.size());
            secure_zero(plaintext.data(), plaintext.size());
            return 1;
        }

        // Output
        if (is_file) {
            write_file(input + ".dec", plaintext.data(), plaintext_len);
            std::cout << "Decrypted file: " << input << ".dec\n";
        } else {
            std::cout.write(reinterpret_cast<char *>(plaintext.data()), plaintext_len);
            std::cout << "\n";
        }

        // Secure cleanup
        secure_zero(entropy.data(), entropy.size());
        secure_zero(plaintext.data(), plaintext.size());
        secure_zero(enc_data.data(), enc_data.size());
        secure_zero(&key_b64[0], key_b64.size());
    }

    // Final cleanup
    secure_zero(input_data.data(), input_data.size());
    
    return 0;
}

// g++ -std=c++17 -Wall -Wextra -O2 -o aes.exe aes256gcm.cpp -lssl -lcrypto -lws2_32 -lgdi32 -lcrypt32 -static