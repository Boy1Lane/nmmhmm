#pragma once
#include <unordered_map>
#include "../common/AppProtocol.h"

using namespace std;

class UserManager {
private:
    unordered_map<string, User> users;   // username -> User
    unordered_map<string, string> activeTokens; // token -> username (Quản lý Session)
    string dbPath;

    void load();
    void save();
    string generateToken(); // Hàm sinh chuỗi ngẫu nhiên

public:
    UserManager(const string& path);

    // Đăng ký (Lưu User + Public Key)
    bool registerUser(const string& username,
        const vector<unsigned char>& passHash,
        const vector<unsigned char>& salt,
        const vector<unsigned char>& publicKey);

    // Đăng nhập: Trả về Token nếu đúng pass (Pass check ở đây giả lập)
    string login(const string& username, const vector<unsigned char>& inputHash);

    // Kiểm tra Token hợp lệ không
    string validateToken(const string& token);

    // Lấy Public Key của user khác (để Alice mã hóa cho Bob)
    vector<unsigned char> getPublicKey(const string& username);

    // Lấy Salt của user (để trả về cho Client lúc login)
    string getSalt(const string& username);

    void logout(const string& token);
};