#include "CryptoUtils.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/kdf.h>
#include <stdexcept>
#include <sstream>
#include <iomanip>

// Cần cài OpenSSL và link với -lssl -lcrypto

// ------------------ Helpers: Bytes <-> Hex ------------------
static std::string BytesToHexInternal(const unsigned char* data, size_t len) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) {
        oss << std::setw(2) << static_cast<int>(data[i]);
    }
    return oss.str();
}

std::string CryptoUtils::BytesToHex(const std::vector<unsigned char>& data) {
    return BytesToHexInternal(data.data(), data.size());
}

std::vector<unsigned char> CryptoUtils::HexToBytes(const std::string& hex) {
    if (hex.size() % 2 != 0) throw std::runtime_error("Invalid hex length");
    std::vector<unsigned char> out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        unsigned int byte = 0;
        std::istringstream iss(hex.substr(i, 2));
        iss >> std::hex >> byte;
        out.push_back(static_cast<unsigned char>(byte));
    }
    return out;
}

// ------------------ Hashing / Salt / UUID ------------------
std::string CryptoUtils::GenerateSalt() {
    unsigned char buf[16];
    // Sinh ngẫu nhiên 16 bytes
    if (RAND_bytes(buf, sizeof(buf)) != 1) throw std::runtime_error("RAND_bytes failed");
    return BytesToHexInternal(buf, sizeof(buf));
}

std::string CryptoUtils::GenerateUUID() {
    unsigned char buf[16];
    if (RAND_bytes(buf, sizeof(buf)) != 1) throw std::runtime_error("RAND_bytes failed");
    // Đặt các bit theo chuẩn UUID v4
    buf[6] = (buf[6] & 0x0F) | 0x40;
    buf[8] = (buf[8] & 0x3F) | 0x80;
    return BytesToHexInternal(buf, sizeof(buf));
}

std::string CryptoUtils::HashPassword(const std::string& password, const std::string& salt) {
    // Hash mật khẩu với SHA-256 (password + salt)
    std::string combined = password + salt;
    unsigned char out[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(combined.data()), combined.size(), out);
    return BytesToHexInternal(out, SHA256_DIGEST_LENGTH);
}

// ------------------ AES-256-CBC Encrypt/Decrypt ------------------
void CryptoUtils::GenerateAESParams(std::vector<unsigned char>& outKey, std::vector<unsigned char>& outIV) {
    outKey.resize(32); // 256-bit
    outIV.resize(16);  // 128-bit
    if (RAND_bytes(outKey.data(), (int)outKey.size()) != 1) throw std::runtime_error("RAND_bytes failed for key");
    if (RAND_bytes(outIV.data(), (int)outIV.size()) != 1) throw std::runtime_error("RAND_bytes failed for iv");
}

std::vector<unsigned char> CryptoUtils::EncryptAES(
    const std::vector<unsigned char>& plain,
    const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& iv
) {
    if (key.size() != 32) throw std::runtime_error("AES key must be 32 bytes");
    if (iv.size() != 16) throw std::runtime_error("AES IV must be 16 bytes");

    // Tạo context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    // Khởi tạo AES-256-CBC
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptInit_ex failed");
    }

    // Thực hiện mã hóa
    std::vector<unsigned char> out;
    out.resize(plain.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));

    int outLen1 = 0;
    if (EVP_EncryptUpdate(ctx, out.data(), &outLen1, plain.data(), (int)plain.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptUpdate failed");
    }

    int outLen2 = 0;
    if (EVP_EncryptFinal_ex(ctx, out.data() + outLen1, &outLen2) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptFinal_ex failed (padding?)");
    }

    out.resize(outLen1 + outLen2);
    EVP_CIPHER_CTX_free(ctx);
    return out;
}

std::vector<unsigned char> CryptoUtils::DecryptAES(
    const std::vector<unsigned char>& cipher,
    const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& iv
) {
    if (key.size() != 32) throw std::runtime_error("AES key must be 32 bytes");
    if (iv.size() != 16) throw std::runtime_error("AES IV must be 16 bytes");

    // Tạo context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    // Khởi tạo AES-256-CBC
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptInit_ex failed");
    }

    // Thực hiện giải mã 
    std::vector<unsigned char> out;
    out.resize(cipher.size());

    int outLen1 = 0;
    if (EVP_DecryptUpdate(ctx, out.data(), &outLen1, cipher.data(), (int)cipher.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptUpdate failed");
    }

    int outLen2 = 0;
    if (EVP_DecryptFinal_ex(ctx, out.data() + outLen1, &outLen2) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptFinal_ex failed: wrong key or corrupted data");
    }

    out.resize(outLen1 + outLen2);
    EVP_CIPHER_CTX_free(ctx);
    return out;
}

// ------------------ Diffie-Hellman (EVP_PKEY/DH) ------------------

void CryptoUtils::GenerateDHKeys(std::string& outPrivateKey, std::string& outPublicKey) {
    // Tạo context từ tên nhóm chuẩn 2048-bit MODP
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "DH", nullptr);
    if (!ctx) throw std::runtime_error("EVP_PKEY_CTX_new_from_name failed");

    if (EVP_PKEY_paramgen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("EVP_PKEY_paramgen_init failed");
    }

    // Dùng nhóm MODP 2048-bit (tốc độ nhanh, an toàn)
    if (EVP_PKEY_CTX_set_dh_paramgen_prime_len(ctx, 2048) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("set prime length failed");
    }

    EVP_PKEY* params = nullptr;
    if (EVP_PKEY_paramgen(ctx, &params) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("paramgen failed");
    }
    EVP_PKEY_CTX_free(ctx);

    // Sinh keypair từ param
    EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new(params, nullptr);
    if (!kctx) {
        EVP_PKEY_free(params);
        throw std::runtime_error("EVP_PKEY_CTX_new for keygen failed");
    }
    if (EVP_PKEY_keygen_init(kctx) <= 0) {
        EVP_PKEY_free(params);
        EVP_PKEY_CTX_free(kctx);
        throw std::runtime_error("keygen_init failed");
    }

    EVP_PKEY* keypair = nullptr;
    if (EVP_PKEY_keygen(kctx, &keypair) <= 0) {
        EVP_PKEY_free(params);
        EVP_PKEY_CTX_free(kctx);
        throw std::runtime_error("keygen failed");
    }

    EVP_PKEY_free(params);
    EVP_PKEY_CTX_free(kctx);

    // Xuất PEM private/public
    BIO* bioPri = BIO_new(BIO_s_mem());
    BIO* bioPub = BIO_new(BIO_s_mem());
    if (!bioPri || !bioPub) {
        EVP_PKEY_free(keypair);
        throw std::runtime_error("BIO_new failed");
    }

    if (!PEM_write_bio_PrivateKey(bioPri, keypair, nullptr, nullptr, 0, nullptr, nullptr) ||
        !PEM_write_bio_PUBKEY(bioPub, keypair)) {
        BIO_free(bioPri);
        BIO_free(bioPub);
        EVP_PKEY_free(keypair);
        throw std::runtime_error("PEM_write_bio failed");
    }

    char* pData = nullptr;
    long len = BIO_get_mem_data(bioPri, &pData);
    outPrivateKey.assign(pData, (size_t)len);

    len = BIO_get_mem_data(bioPub, &pData);
    outPublicKey.assign(pData, (size_t)len);

    BIO_free(bioPri);
    BIO_free(bioPub);
    EVP_PKEY_free(keypair);
}

// ----------------- ComputeSharedSecret tương thích -----------------
std::vector<unsigned char> CryptoUtils::ComputeSharedSecret(
    const std::string& myPrivateKey,
    const std::string& otherPublicKey
) {
    BIO* bioPri = BIO_new_mem_buf(myPrivateKey.data(), (int)myPrivateKey.size());
    BIO* bioPub = BIO_new_mem_buf(otherPublicKey.data(), (int)otherPublicKey.size());
    if (!bioPri || !bioPub) throw std::runtime_error("BIO_new_mem_buf failed");

    EVP_PKEY* pri = PEM_read_bio_PrivateKey(bioPri, nullptr, nullptr, nullptr);
    EVP_PKEY* pub = PEM_read_bio_PUBKEY(bioPub, nullptr, nullptr, nullptr);
    BIO_free(bioPri);
    BIO_free(bioPub);

    if (!pri || !pub) {
        if (pri) EVP_PKEY_free(pri);
        if (pub) EVP_PKEY_free(pub);
        throw std::runtime_error("PEM_read_bio failed to load keys");
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pri, nullptr);
    if (!ctx) {
        EVP_PKEY_free(pri);
        EVP_PKEY_free(pub);
        throw std::runtime_error("EVP_PKEY_CTX_new failed");
    }

    if (EVP_PKEY_derive_init(ctx) != 1 ||
        EVP_PKEY_derive_set_peer(ctx, pub) != 1) {
        EVP_PKEY_free(pri);
        EVP_PKEY_free(pub);
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("EVP_PKEY_derive init/set_peer failed");
    }

    size_t secretLen = 0;
    if (EVP_PKEY_derive(ctx, nullptr, &secretLen) != 1) {
        EVP_PKEY_free(pri);
        EVP_PKEY_free(pub);
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("EVP_PKEY_derive (size) failed");
    }

    std::vector<unsigned char> secret(secretLen);
    if (EVP_PKEY_derive(ctx, secret.data(), &secretLen) != 1) {
        EVP_PKEY_free(pri);
        EVP_PKEY_free(pub);
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("EVP_PKEY_derive failed");
    }
    secret.resize(secretLen);

    EVP_PKEY_free(pri);
    EVP_PKEY_free(pub);
    EVP_PKEY_CTX_free(ctx);

    return secret;
}