#pragma once
#include <string>
#include <vector>
#include <ctime>

// --- ENUMS ---
enum class AppError {
    SUCCESS = 0,
    ERR_NETWORK,
    ERR_AUTH_FAIL,
    ERR_FILE_NOT_FOUND,
    ERR_ACCESS_DENIED,
    ERR_LINK_EXPIRED,
    ERR_CRYPTO_FAIL,
    ERR_USER_EXIST
};

// --- DATA STRUCTURES ---
struct User {
    std::string username;
    std::vector<unsigned char> passHash;
    std::vector<unsigned char> salt;
    std::vector<unsigned char> publicKey;
};

struct ShareInfo {
    std::string targetUser;
    time_t expireTime;
    std::string encryptedKey; // Key đã mã hóa cho người nhận
};

// Gói tin phản hồi chuẩn từ Server
struct ServerResponse {
    AppError status;
    std::string message;
    std::string payloadData; // JSON hoặc Hex String
};