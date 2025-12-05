#pragma once
#include <string>
#include <map>
#include <vector>
#include <ctime>

// --- ĐÂY CHÍNH LÀ FILE FileStructs.h CŨ CỦA BẠN ---

// Bản ghi lưu trong JSON của Server
struct ShareRecord {
    std::string recipientUser;
    std::string encryptedKey;
    std::time_t expirationTime;
    std::string urlToken;
};

// Metadata quản lý file trên ổ cứng Server
struct FileMetadata {
    std::string fileID;
    std::string owner;
    std::string filePath;
    std::string encryptedKeyOwner; // Key của chủ sở hữu

    // Map quản lý danh sách share
    std::map<std::string, ShareRecord> shares;
};