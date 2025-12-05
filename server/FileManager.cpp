#include "FileManager.h"
#include <fstream>
#include <iostream>
#include "../common/json.hpp"
#include <cstdio>
#include "../common/CryptoUtils.h"

using json = nlohmann::json;

FileManager::FileManager(const string& storageFolder, const string& metaJsonPath)
    : storageDir(storageFolder), metaPath(metaJsonPath)
{
    loadMetadata();
}

// JSON LOAD/SAVE
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
                {"exp", record.expirationTime},
                {"token", record.urlToken}
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

                if (jRec.contains("token")) {
                    rec.urlToken = jRec["token"];
                }

                meta.shares[user] = rec;
            }
        }
        fileDB[id] = meta;
    }
}

// Upload File
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

// Share File
string FileManager::shareFile(const string& filename, const string& sender, const string& targetUser, int durationSeconds, const string& encryptedKeyForTarget) {
    if (fileDB.find(filename) == fileDB.end()) return ""; // Trả về rỗng nếu lỗi
    if (fileDB[filename].owner != sender) return "";

    // 1. Sinh Token ngẫu nhiên (UUID)
    string token = CryptoUtils::GenerateUUID();

    ShareRecord record;
    record.recipientUser = targetUser;
    record.encryptedKey = encryptedKeyForTarget;
    record.expirationTime = time(0) + durationSeconds;
    record.urlToken = token; // <--- Lưu Token vào đây

    fileDB[filename].shares[targetUser] = record;
    saveMetadata();

    return token; // Trả về token để ServerCore tạo URL
}

// Hủy share
bool FileManager::revokeShare(const string& filename, const string& owner, const string& targetUser) {
    //Check file tồn tại
    auto itFile = fileDB.find(filename);
    if (itFile == fileDB.end()) return false;

    // Check quyền chủ sở hữu (Chỉ chủ mới được hủy)
    FileMetadata& meta = itFile->second;
    if (meta.owner != owner) return false;

    // Check xem có đang share cho targetUser không
    if (meta.shares.find(targetUser) == meta.shares.end()) {
        return false; // Chưa từng share cho người này
    }

    // Xóa khỏi map và lưu lại
    meta.shares.erase(targetUser);
    saveMetadata();

    return true;
}

// Tải File
vector<unsigned char> FileManager::getFile(const string& filename, const string& requester, AppError& outError, string& outEncryptedKey) {
    outError = AppError::SUCCESS;

    // 1. Check file tồn tại
    if (fileDB.find(filename) == fileDB.end()) {
        outError = AppError::ERR_FILE_NOT_FOUND;
        return {};
    }

    FileMetadata& meta = fileDB[filename];

    // 2. Check quyền truy cập (CHỈ CHO PHÉP OWNER)
    if (requester == meta.owner) {
        outEncryptedKey = meta.encryptedKeyOwner; // Trả về key của chủ
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

vector<unsigned char> FileManager::getFileByLink(const string& token, const string& requester, AppError& outError, string& outEncryptedKey, string& outFilename) {
    outError = AppError::ERR_FILE_NOT_FOUND;

    // Duyệt qua tất cả các file để tìm Token (Cách đơn giản nhất)
    // (Nếu hệ thống lớn, nên tạo 1 map riêng map<token, fileID> để tra cứu O(1))
    for (auto& [fileID, meta] : fileDB) {
        for (auto it = meta.shares.begin(); it != meta.shares.end(); ++it) {
            ShareRecord& record = it->second;

            // Tìm thấy Token khớp
            if (record.urlToken == token) {
                // 1. Check người nhận (Bob có đúng là người đang request không?)
                if (record.recipientUser != requester) {
                    outError = AppError::ERR_ACCESS_DENIED;
                    return {};
                }

                // 2. Check hạn giờ
                if (time(0) > record.expirationTime) {
                    outError = AppError::ERR_LINK_EXPIRED;
                    meta.shares.erase(it); // Xóa share hết hạn
                    saveMetadata();
                    return {};
                }

                // 3. OK -> Lấy dữ liệu trả về
                outEncryptedKey = record.encryptedKey;
                outFilename = meta.fileID; // Trả về tên file gốc để Client lưu

                // Đọc file vật lý
                ifstream fin(meta.filePath, ios::binary | ios::ate);
                if (!fin) return {};
                size_t size = fin.tellg();
                fin.seekg(0, ios::beg);
                vector<unsigned char> buffer(size);
                fin.read((char*)buffer.data(), size);

                outError = AppError::SUCCESS;
                return buffer;
            }
        }
    }
    return {};
}

// Liệt kệ file
vector<string> FileManager::listFiles(const string& username) {
    vector<string> list;
    for (const auto& [id, meta] : fileDB) {
        if (meta.owner == username) {
            list.push_back(meta.fileID);
        }
    }
    return list;
}

// Xóa file
bool FileManager::deleteFile(const string& filename, const string& requester) {
    // Kiểm tra file có tồn tại trong DB không
    auto it = fileDB.find(filename);
    if (it == fileDB.end()) return false;

    // Kiểm tra quyền sở hữu (Chỉ Owner mới được xóa)
    if (it->second.owner != requester) return false;

    // Xóa file vật lý trên ổ cứng
    string filePath = it->second.filePath;
    if (remove(filePath.c_str()) != 0) {
        perror("[ERROR] Khong the xoa file");
    }

    // Xóa khỏi Metadata
    fileDB.erase(it);
    saveMetadata();

    return true;
}