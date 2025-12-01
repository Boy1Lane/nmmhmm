#include "FileManager.h"
#include <fstream>
#include <iostream>
#include "../common/json.hpp"

using json = nlohmann::json;

FileManager::FileManager(const string& storageFolder, const string& metaJsonPath)
    : storageDir(storageFolder), metaPath(metaJsonPath)
{
    loadMetadata();
}

// ---------------- LƯU FILE (UPLOAD) ----------------
void FileManager::saveFile(const string& filename, const vector<unsigned char>& data, const string& owner, const string& ownerEncryptedKey) {
    // 1. Lưu file vật lý
    string fullPath = storageDir + filename;
    ofstream fout(fullPath, ios::binary);
    if (fout) {
        fout.write((char*)data.data(), data.size());
        fout.close();
    }

    // 2. Tạo Metadata mới
    FileMetadata meta;
    meta.fileID = filename;
    meta.owner = owner;
    meta.filePath = fullPath;
    meta.encryptedKeyOwner = ownerEncryptedKey; // Key để owner tự giải mã sau này

    fileDB[filename] = meta;
    saveMetadata();
}

// ---------------- CHIA SẺ FILE (SHARE) ----------------
// Trong FileManager.cpp
bool FileManager::shareFile(const string& filename, const string& sender, const string& targetUser, int durationSeconds, const string& encryptedKeyForTarget) {
    // 1. Kiểm tra file có tồn tại không
    if (fileDB.find(filename) == fileDB.end()) return false;

    // 2. QUAN TRỌNG: Kiểm tra quyền sở hữu
    // Chỉ chủ sở hữu mới được quyền share file
    if (fileDB[filename].owner != sender) {
        return false; // Từ chối nếu không phải chính chủ
    }

    // 3. Tạo bản ghi share (Giữ nguyên logic cũ)
    ShareRecord record;
    record.recipientUser = targetUser;
    record.encryptedKey = encryptedKeyForTarget;
    record.expirationTime = time(0) + durationSeconds;

    fileDB[filename].shares[targetUser] = record;
    saveMetadata();

    return true;
}

// ---------------- TẢI FILE (DOWNLOAD) ----------------
vector<unsigned char> FileManager::getFile(const string& filename, const string& requester, AppError& outError, string& outEncryptedKey) {
    outError = AppError::SUCCESS;

    // 1. Check file tồn tại
    if (fileDB.find(filename) == fileDB.end()) {
        outError = AppError::ERR_FILE_NOT_FOUND;
        return {};
    }

    FileMetadata& meta = fileDB[filename];
    time_t now = time(0);

    // 2. Check quyền truy cập
    // Trường hợp A: Requester là chủ sở hữu
    if (requester == meta.owner) {
        outEncryptedKey = meta.encryptedKeyOwner; // Trả về key của chủ
    }
    // Trường hợp B: Requester là người được share
    else if (meta.shares.count(requester)) {
        ShareRecord& record = meta.shares[requester];

        // Check hạn giờ
        if (now > record.expirationTime) {
            outError = AppError::ERR_LINK_EXPIRED;
            meta.shares.erase(requester); // Xóa quyền đã hết hạn
            saveMetadata();
            return {};
        }

        outEncryptedKey = record.encryptedKey; // Trả về key share cho Bob
    }
    else {
        outError = AppError::ERR_ACCESS_DENIED;
        return {};
    }

    // 3. Đọc file vật lý
    ifstream fin(meta.filePath, ios::binary | ios::ate);
    if (!fin) {
        outError = AppError::ERR_FILE_NOT_FOUND;
        return {};
    }
    size_t size = fin.tellg();
    fin.seekg(0, ios::beg);
    vector<unsigned char> buffer(size);
    fin.read((char*)buffer.data(), size);

    return buffer;
}

// ---------------- JSON LOAD/SAVE (Cập nhật cấu trúc mới) ----------------
void FileManager::saveMetadata() {
    json jRoot;
    for (auto const& [id, meta] : fileDB) {
        json jMeta;
        jMeta["owner"] = meta.owner;
        jMeta["path"] = meta.filePath;
        jMeta["key_owner"] = meta.encryptedKeyOwner;

        json jShares = json::object();
        for (auto const& [user, record] : meta.shares) {
            jShares[user] = {
                {"key", record.encryptedKey},
                {"exp", record.expirationTime}
            };
        }
        jMeta["shares"] = jShares;
        jRoot[id] = jMeta;
    }
    ofstream fout(metaPath);
    fout << jRoot.dump(4);
}

void FileManager::loadMetadata() {
    ifstream fin(metaPath);
    if (!fin) return;
    json jRoot;
    fin >> jRoot;

    fileDB.clear();
    for (auto& [id, jMeta] : jRoot.items()) {
        FileMetadata meta;
        meta.fileID = id;
        meta.owner = jMeta["owner"];
        meta.filePath = jMeta["path"];
        meta.encryptedKeyOwner = jMeta["key_owner"];

        if (jMeta.contains("shares")) {
            for (auto& [user, jRec] : jMeta["shares"].items()) {
                ShareRecord rec;
                rec.recipientUser = user;
                rec.encryptedKey = jRec["key"];
                rec.expirationTime = jRec["exp"];
                meta.shares[user] = rec;
            }
        }
        fileDB[id] = meta;
    }
}