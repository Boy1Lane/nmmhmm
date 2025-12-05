#pragma once
#include <string>
#include <vector>
#include <winsock2.h> // Dùng socket để gửi lệnh
#include "../common/AppProtocol.h"
#include <direct.h> // Thư viện Windows để tạo thư mục (_mkdir)
#include <sys/stat.h> // Để kiểm tra thư mục tồn tại

class ClientCore {
private:
    SOCKET serverSocket;

    // --- TRẠNG THÁI NGƯỜI DÙNG (STATE) ---
    std::string currentUsername;
    std::string sessionToken;
    std::string currentPassHashHex; // Lưu tạm để unwrap key của chính mình
    std::string myPrivateKey;       // Load từ file .priv khi login

    // --- HELPER NETWORK ---
    // Gửi chuỗi lệnh và nhận phản hồi
    ServerResponse sendRequest(const std::string& cmd);

    // Tách chuỗi theo ký tự |
    std::vector<std::string> split(const std::string& s, char delimiter);

    // Helper File
    std::vector<unsigned char> readFile(const std::string& path);
    void writeFile(const std::string& path, const std::vector<unsigned char>& data);

    // --- QUẢN LÝ STORAGE VÀ KEY---
    const std::string CLIENT_STORAGE_ROOT = "../download/";
    const std::string CLIENT_KEY_ROOT = "../privatekey/";

public:
    ClientCore(SOCKET sock);

    // --- CÁC TÍNH NĂNG NGƯỜI DÙNG ---

    // Đăng ký: Sinh cặp Key DH -> Gửi Public Key lên Server -> Lưu Private Key xuống đĩa
    void actionRegister();

    // Đăng nhập: Hash pass -> Gửi lên Server -> Nhận Token -> Load Private Key
    void actionLogin();

    // Upload: Sinh AES Key -> Encrypt File -> Encrypt Key (bằng PassHash) -> Gửi
    void actionUpload();

    // Share: Lấy PubKey Bob -> Tính Secret -> Encrypt Key (bằng Secret) -> Gửi
    void actionShare();

    // Hủy share
    void actionRevokeShare();

    // Download: Tải về -> Decrypt Key (bằng PassHash hoặc Secret) -> Decrypt File
    void actionDownload();

    void actionDownloadViaLink();

    // Đăng xuất
    void actionLogout();

    // Liệt kê danh sách files upload
    void actionListFiles();

    // Xóa file
    void actionDeleteFile();

    bool isLoggedIn() const { return !sessionToken.empty(); }
};