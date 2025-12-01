#include "UserManager.h"
#include <fstream>
#include <openssl/crypto.h> // For secure comparison
#include <cstdlib>
#include "../common/json.hpp" // Đảm bảo bạn đã có thư viện nlohmann/json
#include "../common/CryptoUtils.h"

using json = nlohmann::json;
using namespace std;

// Helper chuyển đổi vector <-> json
static json vectorToJson(const vector<unsigned char>& v) { return json(v); }
static vector<unsigned char> jsonToVector(const json& j) { return j.get<vector<unsigned char>>(); }

UserManager::UserManager(const string& path) : dbPath(path) {
    load();
    srand(time(0)); // Seed cho random token
}

void UserManager::load() {
    ifstream fin(dbPath);
    if (!fin) return;
    json j;
    fin >> j;
    for (auto& [username, data] : j.items()) {
        User u;
        u.username = username;
        u.passHash = CryptoUtils::HexToBytes(data["PassHash"].get<string>());
        u.salt = CryptoUtils::HexToBytes(data["Salt"].get<string>());
        u.publicKey = CryptoUtils::HexToBytes(data["PublicKey"].get<string>());
        users[username] = u;
    }
}

void UserManager::save() {
    json j;
    for (auto& [username, u] : users) {
        j[username] = {
            {"PassHash", CryptoUtils::BytesToHex(u.passHash)},
            {"Salt",     CryptoUtils::BytesToHex(u.salt)},
            {"PublicKey", CryptoUtils::BytesToHex(u.publicKey)}
        };
    }
    ofstream fout(dbPath);
    fout << j.dump(4);
}

bool UserManager::registerUser(const string& username, const vector<unsigned char>& passHash, const vector<unsigned char>& salt, const vector<unsigned char>& publicKey) {
    if (users.count(username) > 0) return false;
    User u = { username, passHash, salt, publicKey };
    users[username] = u;
    save();
    return true;
}

string UserManager::generateToken() {
    // Tạo token ngẫu nhiên đơn giản
    string chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    string token;
    for (int i = 0; i < 32; ++i) token += chars[rand() % chars.length()];
    return token;
}

string UserManager::login(const string& username, const vector<unsigned char>& inputHash) {
    if (users.find(username) == users.end()) return ""; // User does not exist

    const vector<unsigned char>& storedHash = users[username].passHash;
    if (storedHash.size() != inputHash.size()) return "";

    // Use constant-time comparison to prevent timing attacks
    if (CRYPTO_memcmp(storedHash.data(), inputHash.data(), storedHash.size()) == 0) {
        string token = generateToken();
        activeTokens[token] = username;
        return token; // Return token to client
    }
    return "";
}

string UserManager::validateToken(const string& token) {
    if (activeTokens.count(token)) return activeTokens[token]; // Trả về username
    return "";
}

vector<unsigned char> UserManager::getPublicKey(const string& username) {
    if (users.count(username)) return users[username].publicKey;
    return {};
}

string UserManager::getSalt(const string& username) {
    if (users.find(username) != users.end()) {
        // Convert vector<byte> salt sang Hex String để gửi qua mạng
        return CryptoUtils::BytesToHex(users[username].salt);
    }
    return ""; // Trả về rỗng nếu user không tồn tại
}

void UserManager::logout(const string& token) {
    if (activeTokens.count(token)) {
        activeTokens.erase(token);
    }
}