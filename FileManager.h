#include "FileStructs.h"
#include "SharedDefinitions.h"

class FileManager {
private:
    std::map<std::string, FileMetadata> database; // Giả lập DB trong RAM
    const std::string STORAGE_DIR = "Server_Storage/";

public:
    // 1. Upload File Mới
    AppError SaveNewFile(std::string fileID, std::string owner,
        const std::vector<unsigned char>& encryptedContent,
        std::string encryptedKeyOwner);

    // 2. Thêm quyền Share (E2EE + Time Check Logic)
    // encryptedKeyForRecipient: Là FileKey đã được bọc bằng SharedSecret
    AppError AddShare(std::string fileID, std::string recipient,
        std::string encryptedKeyForRecipient, int durationMinutes);

    // 3. Truy cập File (Download Logic)
    // Hàm này phải check: 
    // - User có trong danh sách share không?
    // - Thời gian hiện tại > expirationTime không?
    // Output: Trả về Content + EncryptedKey dành riêng cho user đó
    struct DownloadResult {
        std::vector<unsigned char> content;
        std::string encryptedKey;
        std::string iv;
    };

    std::pair<AppError, DownloadResult> GetFile(std::string fileID, std::string requestUser);

    // 4. (Optional) Kiểm tra URL Token
    // Dùng cho tính năng "Truy cập qua URL tạm thời"
    bool IsUrlTokenValid(std::string token);
};