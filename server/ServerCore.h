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

    // --- CÁC HÀM XỬ LÝ REQUEST TỪ CLIENT ---

    // 1. Đăng ký
    ServerResponse reqRegister(const std::string& username,
        const std::string& passHashHex,
        const std::string& saltHex,
        const std::string& pubKeyHex);

    // 2. Đăng nhập
    ServerResponse reqLogin(const std::string& username, const std::string& inputHashHex);

    // 3. Upload File (Cần Token xác thực)
    ServerResponse reqUpload(const std::string& token,
        const std::string& filename,
        const std::vector<unsigned char>& fileData,
        const std::string& ownerEncryptedKey);

    // 4. Chia sẻ File (Cần Token xác thực)
    ServerResponse reqShare(const std::string& token,
        const std::string& filename,
        const std::string& targetUser,
        int durationMinutes,
        const std::string& encryptedKeyForTarget);

    // 5. Tải File (Cần Token xác thực + Kiểm tra hạn giờ)
    ServerResponse reqDownload(const std::string& token, const std::string& filename);

    // 6. Lấy Public Key của user khác (Để Client thực hiện E2EE)
    ServerResponse reqGetPublicKey(const std::string& token, const std::string& targetUser);

    // 7. Request lấy Salt (Login Step 1)
    ServerResponse reqGetSalt(const std::string& username);

    ServerResponse reqLogout(const std::string& token);
};