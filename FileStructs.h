#include <map>
#include <ctime>

// Bản ghi chia sẻ (Lưu thông tin cho từng người nhận)
struct ShareRecord {
    std::string recipientUser;      // Người được nhận (Bob)
    std::string encryptedKey;       // Key giải mã (Đã được Alice mã hóa riêng cho Bob)
    std::time_t expirationTime;     // Thời điểm hết hạn riêng cho Bob
    std::string urlToken;           // Token truy cập nhanh (Optional: dùng cho URL sharing)
};

// Metadata của File
struct FileMetadata {
    std::string fileID;
    std::string owner;
    std::string filePath;           // Đường dẫn file mã hóa trên đĩa server
    std::string encryptedKeyOwner;  // Key mã hóa dành riêng cho chủ sở hữu

    // QUAN TRỌNG: Map quản lý danh sách người được share
    // Key: Username người nhận -> Value: Thông tin share
    std::map<std::string, ShareRecord> shares;
};