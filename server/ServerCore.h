#pragma once
#include <string>
#include <vector>
#include "UserManager.h"
#include "FileManager.h"
#include "../common/AppProtocol.h"

class ServerCore {
private:
    UserManager userManager;
    FileManager fileManager;

public:
    // Constructor: Khởi tạo database và storage
    ServerCore(const std::string& storageDir,
        const std::string& userPath,
        const std::string& metaPath);

    // Đăng ký
    ServerResponse reqRegister(const std::string& username,
        const std::string& passHashHex,
        const std::string& saltHex,
        const std::string& pubKeyHex);

    // Đăng nhập
    ServerResponse reqLogin(const std::string& username, const std::string& inputHashHex);

    // Upload File (Cần Token xác thực)
    ServerResponse reqUpload(const std::string& token,
        const std::string& filename,
        const std::vector<unsigned char>& fileData,
        const std::string& ownerEncryptedKey);

    // Chia sẻ File (Cần Token xác thực)
    ServerResponse reqShare(const std::string& token,
        const std::string& filename,
        const std::string& targetUser,
        int durationMinutes,
        const std::string& encryptedKeyForTarget);

    // Hủy chia sẻ
    ServerResponse reqRevokeShare(const std::string& token, const std::string& filename, const std::string& targetUser);

    // Tải File (Cần Token xác thực + Kiểm tra hạn giờ)
    ServerResponse reqDownload(const std::string& token, const std::string& filename);
    ServerResponse reqDownloadViaLink(const std::string& token, const std::string& urlToken);

    // Lấy Public Key của user khác (Để Client thực hiện E2EE)
    ServerResponse reqGetPublicKey(const std::string& token, const std::string& targetUser);

    // Request lấy Salt (Login Step 1)
    ServerResponse reqGetSalt(const std::string& username);

    // Đăng xuất (Sẽ hủy session token)
    ServerResponse reqLogout(const std::string& token);

    // Request danh sách file đã tải lên
    ServerResponse reqListFiles(const std::string& token);

    // Request xóa file
    ServerResponse reqDeleteFile(const std::string& token, const std::string& filename);
};