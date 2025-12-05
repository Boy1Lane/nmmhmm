#pragma once
#include <map>
#include <string>
#include <vector>
#include "../common/AppProtocol.h"
#include "ServerStruct.h"

using namespace std;

class FileManager {
private:
    string storageDir;
    string metaPath;

    // Map: FileID (hoặc Filename) -> Metadata đầy đủ (bao gồm owner, shares, keys)
    map<string, FileMetadata> fileDB;

    void loadMetadata();
    void saveMetadata();

public:
    FileManager(const string& storageFolder, const string& metaJsonPath);

    // Save File: Cần nhận thêm encryptedKey của Owner (để chủ nhân tự mở file mình)
    void saveFile(const string& filename, const vector<unsigned char>& data, const string& owner, const string& ownerEncryptedKey);

    // Share File
    string shareFile(const string& filename, const string& sender, const string& targetUser, int durationSeconds, const string& encryptedKeyForTarget);
    // Hủy share
    bool revokeShare(const string& filename, const string& owner, const string& targetUser);

    // Get File: Trả về nội dung + Key đã mã hóa cho người request
    vector<unsigned char> getFile(const string& filename, const string& requester, AppError& outError, string& outEncryptedKey);
    vector<unsigned char> getFileByLink(const string& token, const string& requester, AppError& outError, string& outEncryptedKey, string& outFilename);

    // Trả về danh sách các File đã tải lên
    vector<string> listFiles(const string& username);

    // Xóa file
    bool deleteFile(const string& filename, const string& requester);
};