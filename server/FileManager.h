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
    // Dùng FileMetadata từ ServerStruct.h thay vì vector<ShareInfo> sơ sài cũ
    map<string, FileMetadata> fileDB;

    void loadMetadata();
    void saveMetadata();

public:
    FileManager(const string& storageFolder, const string& metaJsonPath);

    // 1. Save File: Cần nhận thêm encryptedKey của Owner (để chủ nhân tự mở file mình)
    void saveFile(const string& filename, const vector<unsigned char>& data, const string& owner, const string& ownerEncryptedKey);

    // 2. Share File: Cần nhận thêm encryptedKey cho người được share
    bool shareFile(const string& filename, const string& sender, const string& targetUser, int durationSeconds, const string& encryptedKeyForTarget);

    // 3. Get File: Trả về nội dung + Key đã mã hóa cho người request
    vector<unsigned char> getFile(const string& filename, const string& requester, AppError& outError, string& outEncryptedKey);
};