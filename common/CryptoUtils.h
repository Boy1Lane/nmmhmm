#pragma once
#include "AppProtocol.h"

class CryptoUtils {
public:
    // --- 1. TIỆN ÍCH DATA (Giải quyết vấn đề gửi Binary qua JSON) ---
    static std::string BytesToHex(const std::vector<unsigned char>& data);
    static std::vector<unsigned char> HexToBytes(const std::string& hex);

    // --- 2. HASHING (Xử lý Password) ---
    static std::string GenerateSalt(); // Random 16 bytes hex
    static std::string GenerateUUID(); // Random ID cho File/Token
    static std::string HashPassword(const std::string& password, const std::string& salt);

    // --- 3. AES ENCRYPTION (Xử lý File) ---
    // Input: Plaintext -> Output: Ciphertext
    static std::vector<unsigned char> EncryptAES(
        const std::vector<unsigned char>& plain,
        const std::vector<unsigned char>& key,
        const std::vector<unsigned char>& iv
    );

    // Input: Ciphertext -> Output: Plaintext
    // Throw exception hoặc trả về rỗng nếu sai Key
    static std::vector<unsigned char> DecryptAES(
        const std::vector<unsigned char>& cipher,
        const std::vector<unsigned char>& key,
        const std::vector<unsigned char>& iv
    );

    // Tạo Key/IV ngẫu nhiên
    static void GenerateAESParams(std::vector<unsigned char>& outKey, std::vector<unsigned char>& outIV);

    // --- 4. DIFFIE-HELLMAN (E2EE Key Exchange) ---
    // Tạo cặp khóa Private/Public (Format: PEM String hoặc Hex)
    static void GenerateDHKeys(std::string& outPrivateKey, std::string& outPublicKey);

    // Tính Shared Secret từ Private của mình + Public của người khác
    static std::vector<unsigned char> ComputeSharedSecret(
        const std::string& myPrivateKey,
        const std::string& otherPublicKey
    );
};