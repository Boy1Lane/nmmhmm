#include "CryptoUtils.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/kdf.h>
#include <openssl/provider.h> // <--- MỚI: Bắt buộc để dùng ffdhe2048 trên Windows
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <vector>
#include <iostream>

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
    if (RAND_bytes(buf, sizeof(buf)) != 1) throw std::runtime_error("RAND_bytes failed");
    return BytesToHexInternal(buf, sizeof(buf));
}

std::string CryptoUtils::GenerateUUID() {
    unsigned char buf[16];
    if (RAND_bytes(buf, sizeof(buf)) != 1) throw std::runtime_error("RAND_bytes failed");
    buf[6] = (buf[6] & 0x0F) | 0x40;
    buf[8] = (buf[8] & 0x3F) | 0x80;
    return BytesToHexInternal(buf, sizeof(buf));
}

std::string CryptoUtils::HashPassword(const std::string& password, const std::string& salt) {
    std::string combined = password + salt;
    unsigned char out[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(combined.data()), combined.size(), out);
    return BytesToHexInternal(out, SHA256_DIGEST_LENGTH);
}

// ------------------ AES-256-CBC Encrypt/Decrypt ------------------
void CryptoUtils::GenerateAESParams(std::vector<unsigned char>& outKey, std::vector<unsigned char>& outIV) {
    outKey.resize(32);
    outIV.resize(16);
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

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptInit_ex failed");
    }

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

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptInit_ex failed");
    }

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
        // Lưu ý: Nếu decrypt sai key, OpenSSL thường lỗi ở bước này
        throw std::runtime_error("EVP_DecryptFinal_ex failed (Wrong Key?)");
    }

    out.resize(outLen1 + outLen2);
    EVP_CIPHER_CTX_free(ctx);
    return out;
}

// ------------------ Diffie-Hellman (CHUẨN HÓA ffdhe2048) ------------------

void CryptoUtils::GenerateDHKeys(std::string& outPrivateKey, std::string& outPublicKey) {
    // 1. Load Provider (Cực kỳ quan trọng để fix lỗi lần trước của bạn)
    // Static để chỉ load 1 lần trong suốt vòng đời chương trình
    static bool providerLoaded = false;
    if (!providerLoaded) {
        OSSL_PROVIDER_load(nullptr, "default");
        OSSL_PROVIDER_load(nullptr, "legacy");
        providerLoaded = true;
    }

    // 2. Tạo Context cho thuật toán DH
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_from_name(nullptr, "DH", nullptr);
    if (!pctx) throw std::runtime_error("OpenSSL: Khong the khoi tao DH Context");

    // 3. Init Keygen
    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        throw std::runtime_error("OpenSSL: Keygen init that bai");
    }

    // 4. SỬ DỤNG NHÓM CHUẨN RFC 7919 (ffdhe2048)
    // Đây là bước thay thế cho việc tự sinh param ngẫu nhiên
    if (EVP_PKEY_CTX_set_group_name(pctx, "ffdhe2048") <= 0) {
        // Fallback: Nếu phiên bản OpenSSL quá cũ (dưới 3.0) không hỗ trợ ffdhe2048 string,
        // ta sẽ gặp lỗi ở đây. Nhưng bạn đang dùng OpenSSL 3.x nên yên tâm.
        EVP_PKEY_CTX_free(pctx);
        unsigned long err = ERR_get_error();
        char buf[256];
        ERR_error_string_n(err, buf, sizeof(buf));
        std::string msg = "OpenSSL: Khong ho tro group 'ffdhe2048'. Error: ";
        msg += buf;
        throw std::runtime_error(msg);
    }

    // 5. Sinh khóa (Rất nhanh vì param đã có sẵn)
    EVP_PKEY* keypair = nullptr;
    if (EVP_PKEY_keygen(pctx, &keypair) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        throw std::runtime_error("OpenSSL: Sinh khoa DH that bai");
    }

    EVP_PKEY_CTX_free(pctx);

    // 6. Xuất ra PEM String
    BIO* bioPri = BIO_new(BIO_s_mem());
    BIO* bioPub = BIO_new(BIO_s_mem());
    if (!bioPri || !bioPub) {
        EVP_PKEY_free(keypair);
        throw std::runtime_error("BIO_new failed");
    }

    if (!PEM_write_bio_PrivateKey(bioPri, keypair, nullptr, nullptr, 0, nullptr, nullptr) ||
        !PEM_write_bio_PUBKEY(bioPub, keypair)) {
        BIO_free(bioPri); BIO_free(bioPub); EVP_PKEY_free(keypair);
        throw std::runtime_error("Loi ghi PEM key");
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

// ----------------- ComputeSharedSecret -----------------
std::vector<unsigned char> CryptoUtils::ComputeSharedSecret(
    const std::string& myPrivateKey,
    const std::string& otherPublicKey
) {
    // Load Private Key
    BIO* bioPri = BIO_new_mem_buf(myPrivateKey.data(), (int)myPrivateKey.size());
    EVP_PKEY* pri = PEM_read_bio_PrivateKey(bioPri, nullptr, nullptr, nullptr);
    BIO_free(bioPri);
    if (!pri) throw std::runtime_error("Khong load duoc Private Key (PEM sai format?)");

    // Load Public Key
    BIO* bioPub = BIO_new_mem_buf(otherPublicKey.data(), (int)otherPublicKey.size());
    EVP_PKEY* pub = PEM_read_bio_PUBKEY(bioPub, nullptr, nullptr, nullptr);
    BIO_free(bioPub);
    if (!pub) {
        EVP_PKEY_free(pri);
        throw std::runtime_error("Khong load duoc Public Key (PEM sai format?)");
    }

    // Tạo Context Derive
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pri, nullptr);
    if (!ctx) {
        EVP_PKEY_free(pri); EVP_PKEY_free(pub);
        throw std::runtime_error("EVP_PKEY_CTX_new failed");
    }

    // Init Derive
    if (EVP_PKEY_derive_init(ctx) <= 0) {
        EVP_PKEY_free(pri); EVP_PKEY_free(pub); EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("EVP_PKEY_derive_init failed");
    }

    // Set Peer (Ghép Public Key của người kia vào)
    if (EVP_PKEY_derive_set_peer(ctx, pub) <= 0) {
        EVP_PKEY_free(pri); EVP_PKEY_free(pub); EVP_PKEY_CTX_free(ctx);
        // Đây chính là chỗ từng gây lỗi "set_peer failed" do lệch Group Param
        throw std::runtime_error("Loi: Key khong khop tham so DH (ffdhe2048 mismatch?)");
    }

    // Tính kích thước Secret
    size_t secretLen = 0;
    if (EVP_PKEY_derive(ctx, nullptr, &secretLen) <= 0) {
        EVP_PKEY_free(pri); EVP_PKEY_free(pub); EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("EVP_PKEY_derive (size) failed");
    }

    // Tính Secret thật
    std::vector<unsigned char> secret(secretLen);
    if (EVP_PKEY_derive(ctx, secret.data(), &secretLen) <= 0) {
        EVP_PKEY_free(pri); EVP_PKEY_free(pub); EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("EVP_PKEY_derive failed");
    }
    secret.resize(secretLen);

    EVP_PKEY_free(pri);
    EVP_PKEY_free(pub);
    EVP_PKEY_CTX_free(ctx);

    return secret;
}