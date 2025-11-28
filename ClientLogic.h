#include "SharedDefinitions.h";

class ClientLogic {
private:
    std::string myPrivateKey; // Key bí mật DH (Load từ file local)
    std::string myUsername;
    std::string sessionToken;

public:
    // --- AUTH ---
    // Lúc đăng ký: Tự sinh DH Keypair -> Gửi Public lên Server, Lưu Private ở máy
    void RegisterFlow();
    void LoginFlow();

    // --- UPLOAD (Encryption) ---
    // 1. Đọc file -> Tạo AES Key/IV -> Mã hóa File
    // 2. Mã hóa AES Key bằng chính Password của mình (Key Wrapping)
    // 3. Gửi lên Server
    void UploadFlow(std::string path);

    // --- SHARE (Complex E2EE Logic) ---
    // Kịch bản: Share cho Bob trong 10 phút
    void ShareFlow(std::string fileID, std::string bobUsername, int minutes) {
        // B1: Gọi API GetPublicKey(bobUsername) từ Server
        std::string bobPubKey = ...;

        // B2: Tính Shared Secret (Dùng TV1 Library)
        // secret = CryptoUtils::ComputeSharedSecret(myPrivateKey, bobPubKey);

        // B3: Lấy FileKey gốc (đang cache trong RAM hoặc giải mã lại)
        std::vector<unsigned char> fileKey = ...;

        // B4: Bọc Key (Key Wrapping)
        // wrappedKey = CryptoUtils::EncryptAES(fileKey, key=secret, ...)

        // B5: Gửi lên Server
        // Send: {cmd: "SHARE", file: fileID, to: Bob, key: wrappedKey, time: 10}
    }

    // --- DOWNLOAD (Decryption) ---
    // 1. Gửi request -> Server check Time -> Trả về Error hoặc Data
    // 2. Nếu Error == ERR_LINK_EXPIRED -> Báo lỗi cho user
    // 3. Nếu OK -> Nhận (EncryptedContent, WrappedKey, SenderPubKey)
    // 4. Tính lại Shared Secret -> Mở WrappedKey -> Có FileKey
    // 5. Mở File -> Lưu xuống đĩa
    void DownloadFlow(std::string fileID);
};