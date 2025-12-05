#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include "ClientCore.h"
#include "../common/CryptoUtils.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <filesystem>
#include "../common/json.hpp"

using namespace std;
namespace fs = std::filesystem;
using json = nlohmann::json;

#define BUFFER_SIZE 1024 * 1024 // 1MB Buffer cho socket

ClientCore::ClientCore(SOCKET sock) : serverSocket(sock) {
    // 1. Tạo thư mục Downloads gốc
    if (!fs::exists(CLIENT_STORAGE_ROOT)) {
        fs::create_directories(CLIENT_STORAGE_ROOT);
    }

    // 2. Tạo thư mục Keys gốc
    if (!fs::exists(CLIENT_KEY_ROOT)) {
        fs::create_directories(CLIENT_KEY_ROOT);
    }
}

// ================= HELPER FUNCTIONS =================

vector<string> ClientCore::split(const string& s, char delimiter) {
    vector<string> tokens;
    string token;
    istringstream tokenStream(s);
    while (getline(tokenStream, token, delimiter)) {
        tokens.push_back(token);
    }
    return tokens;
}

// Trong ClientCore.cpp

ServerResponse ClientCore::sendRequest(const string& cmd) {
    // 1. Gửi lệnh (Giữ nguyên)
    string finalCmd = cmd + "\n";
    send(serverSocket, finalCmd.c_str(), (int)finalCmd.size(), 0);

    // 2. Nhận phản hồi (Giữ nguyên logic append an toàn)
    string rawRes = "";
    char chunk[4096];

    while (true) {
        memset(chunk, 0, sizeof(chunk));
        int bytesReceived = recv(serverSocket, chunk, sizeof(chunk) - 1, 0);

        if (bytesReceived <= 0) return { AppError::ERR_NETWORK, "Mat ket noi Server", "" };

        rawRes.append(chunk, bytesReceived);

        if (!rawRes.empty() && rawRes.back() == '\n') {
            rawRes.pop_back(); // Xóa \n
            break;
        }
    }

    // --- SỬA ĐOẠN PARSE NÀY ---
    // Thay vì split toàn bộ, ta chỉ tách thủ công 2 trường đầu (Status, Message)
    // Để bảo toàn nội dung Payload (có chứa dấu | bên trong)

    ServerResponse res;

    // Tìm dấu | thứ nhất (Ngăn cách Status)
    size_t firstSep = rawRes.find('|');
    if (firstSep == string::npos) return { AppError::ERR_NETWORK, "Loi Protocol (No Status)", "" };

    res.status = (AppError)stoi(rawRes.substr(0, firstSep));

    // Tìm dấu | thứ hai (Ngăn cách Message và Payload)
    size_t secondSep = rawRes.find('|', firstSep + 1);

    if (secondSep == string::npos) {
        // Trường hợp không có payload (Chỉ có STATUS|MESSAGE)
        res.message = rawRes.substr(firstSep + 1);
    }
    else {
        // Có payload
        res.message = rawRes.substr(firstSep + 1, secondSep - firstSep - 1);
        // Lấy toàn bộ phần còn lại làm payload (Chứa cả Key|Data)
        res.payloadData = rawRes.substr(secondSep + 1);
    }

    return res;
}

vector<unsigned char> ClientCore::readFile(const string& path) {
    ifstream file(path, ios::binary | ios::ate);
    if (!file) throw runtime_error("Khong the mo file: " + path);
    streamsize size = file.tellg();
    file.seekg(0, ios::beg);
    vector<unsigned char> buffer(size);
    if (file.read((char*)buffer.data(), size)) return buffer;
    return {};
}

void ClientCore::writeFile(const string& path, const vector<unsigned char>& data) {
    ofstream file(path, ios::binary);
    file.write((char*)data.data(), data.size());
}

// ================= CORE FEATURES =================

void ClientCore::actionRegister() {
    cout << "\n--- DANG KY ---\n";
    while (true) {
        string u, p;
        cout << "Nhap Username (hoac 'exit' de thoat): "; cin >> u;
        if (u == "exit") return;

        cout << "Nhap Password: "; cin >> p;

        // Sinh khóa bảo mật
        string myPub, myPriv;
        CryptoUtils::GenerateDHKeys(myPriv, myPub);
        cout << "[INFO] Sinh khoa thanh cong.\n";

        // Sinh Salt & Hash
        string salt = CryptoUtils::GenerateSalt();
        string passHash = CryptoUtils::HashPassword(p, salt);
        string pubHex = CryptoUtils::BytesToHex(vector<unsigned char>(myPub.begin(), myPub.end()));

        // Gửi lệnh
        string cmd = "REGISTER|" + u + "|" + passHash + "|" + salt + "|" + pubHex;
        ServerResponse res = sendRequest(cmd);

        // XỬ LÝ KẾT QUẢ
        if (res.status == AppError::SUCCESS) {
            cout << "[SUCCESS] " << res.message << endl;

            string userKeyDir = CLIENT_KEY_ROOT + u + "/";

            if (!fs::exists(userKeyDir)) {
                fs::create_directories(userKeyDir);
            }

            string keyPath = userKeyDir + u + ".priv";
            writeFile(keyPath, vector<unsigned char>(myPriv.begin(), myPriv.end()));

            break; // Thoát vòng lặp quay về menu
        }
        else if (res.status == AppError::ERR_USER_EXIST) {
            cout << "[ERROR] Ten dang nhap da bi trung!\n";
            // Không break, vòng lặp while(true) sẽ cho nhập lại
        }
        else {
            cout << "[ERROR] Loi he thong: " << res.message << endl;
            break;
        }
    }
}

void ClientCore::actionLogin() {
    cout << "\n--- DANG NHAP ---\n";
    string u, p;
    cout << "Username: "; cin >> u;
    cout << "Password: "; cin >> p;

    // Load Private Key
    try {
        string keyPath = CLIENT_KEY_ROOT + u + "/" + u + ".priv";

        vector<unsigned char> keyData = readFile(keyPath);
        this->myPrivateKey = string(keyData.begin(), keyData.end());
    }
    catch (...) {
        cout << "[ERROR] Khong tim thay private key, vui long tao tai khoan.\n";
        return;
    }

    // Xin Salt từ Server 
    cout << "[INFO] Dang lay Salt tu Server...\n";
    string cmdSalt = "GETSALT|" + u;
    ServerResponse resSalt = sendRequest(cmdSalt);

    if (resSalt.status != AppError::SUCCESS) {
        cout << "[ERROR] Khong tim thay tai khoan: " << u << endl;
        return;
    }

    string serverSalt = resSalt.payloadData;

    // Hash Password với Salt vừa nhận được
    string passHash = CryptoUtils::HashPassword(p, serverSalt);

    // Gửi Hash lên Server
    string cmdLogin = "LOGIN|" + u + "|" + passHash;
    ServerResponse res = sendRequest(cmdLogin);
    cout << "Server: " << res.message << endl;

    if (res.status == AppError::SUCCESS) {
        this->sessionToken = res.payloadData;
        this->currentUsername = u;
        this->currentPassHashHex = passHash;
    }

    if (!fs::exists(CLIENT_STORAGE_ROOT + u + "/")) {
        fs::create_directories(CLIENT_STORAGE_ROOT + u + "/");
    }
}

void ClientCore::actionUpload() {
    if (!isLoggedIn()) { cout << "Vui long login!\n"; return; }

    string path;
    cout << "\n--- UPLOAD ---\nNhap duong dan file: "; cin >> path;

    try {
        // B1: Đọc file
        vector<unsigned char> plainData = readFile(path);

        // B2: Sinh File Key & IV
        vector<unsigned char> fileKey, fileIV;
        CryptoUtils::GenerateAESParams(fileKey, fileIV);

        // B3: Mã hóa File (AES-CBC)
        vector<unsigned char> cipherData = CryptoUtils::EncryptAES(plainData, fileKey, fileIV);

        // B4: Key Wrapping (Chủ sở hữu tự khóa Key bằng PassHash của mình)
        // Dùng PassHash làm Key để mã hóa FileKey
        vector<unsigned char> kekOwner = CryptoUtils::HexToBytes(currentPassHashHex);
        vector<unsigned char> ivZero(16, 0); // IV cho KeyWrap có thể null
        vector<unsigned char> encryptedFileKey = CryptoUtils::EncryptAES(fileKey, kekOwner, ivZero);

        // B5: Gửi UPLOAD|token|filename|hexContent|hexKey
        // Filename lấy phần đuôi path
        string filename = path.substr(path.find_last_of("/\\") + 1);

        // Protocol yêu cầu Hex String
        string hexContent = CryptoUtils::BytesToHex(cipherData);
        string hexKey = CryptoUtils::BytesToHex(encryptedFileKey);

        // Gửi IV kèm content (Format: IV + Cipher)
        string hexIV = CryptoUtils::BytesToHex(fileIV);
        string finalPayload = hexIV + hexContent; // Ghép IV vào đầu để Server lưu chung

        // Chỉ hỗ trợ file ít hơn 500KB
        if (finalPayload.size() > 500000) {
            cout << "[WARNING] File qua lon!\n";
        }

        string cmd = "UPLOAD|" + sessionToken + "|" + filename + "|" + finalPayload + "|" + hexKey;
        ServerResponse res = sendRequest(cmd);
        cout << "Server: " << res.message << endl;

    }
    catch (exception& e) {
        cout << "[ERROR] " << e.what() << endl;
    }
}

void ClientCore::actionShare() {
    if (!isLoggedIn()) { cout << "Vui long login!\n"; return; }

    string fname, targetUser;
    int mins;
    cout << "\n--- CHIA SE FILE (E2EE) ---\n";
    cout << "Ten file (vd: report.txt): "; cin >> fname;
    cout << "Nguoi nhan (Username): "; cin >> targetUser;
    cout << "Thoi han (phut): "; cin >> mins;

    // --- GIAI ĐOẠN 1: CHUẨN BỊ KEY CỦA NGƯỜI NHẬN ---

    // B1: Lấy Public Key của Target từ Server
    cout << "[1/4] Dang lay Public Key cua " << targetUser << "...\n";
    string cmdKey = "GETKEY|" + sessionToken + "|" + targetUser;
    ServerResponse resKey = sendRequest(cmdKey);

    if (resKey.status != AppError::SUCCESS) {
        cout << "[ERROR] " << resKey.message << endl;
        return;
    }

    // Convert Hex -> Bytes để tính toán
    string targetPubHex = resKey.payloadData;
    vector<unsigned char> targetPubBytes = CryptoUtils::HexToBytes(targetPubHex);
    string targetPubPEM(targetPubBytes.begin(), targetPubBytes.end());

    // B2: Tính Shared Secret (ECDH)
    // Secret = MyPriv + TargetPub
    vector<unsigned char> sharedSecret = CryptoUtils::ComputeSharedSecret(myPrivateKey, targetPubPEM);

    // Hash secret để ra đúng 32 bytes dùng làm Key AES (Session Key)
    string secretHex = CryptoUtils::BytesToHex(sharedSecret);
    string sharedAESKeyHex = CryptoUtils::HashPassword(secretHex, "common_salt");
    vector<unsigned char> kekTarget = CryptoUtils::HexToBytes(sharedAESKeyHex);
    cout << "[INFO] Da thiet lap kenh E2EE voi " << targetUser << ".\n";


    // --- GIAI ĐOẠN 2: LẤY FILE KEY GỐC ---

    // Để share được file, ta cần biết "File Key" gốc của nó.
    // Cách duy nhất là tải Metadata của file về và tự giải mã bằng PassHash của mình.

    cout << "[2/4] Dang lay File Key tu Server...\n";
    // Gửi lệnh DOWNLOAD giả (chỉ để lấy Key về, không cần file content)
    // *Lưu ý*: Server hiện tại trả về cả Content. Để tối ưu, bạn có thể viết thêm API 'GET_METADATA'
    // Nhưng dùng tạm 'DOWNLOAD' cũng được, hơi tốn băng thông tí nhưng code đơn giản.
    string cmdGetFile = "DOWNLOAD|" + sessionToken + "|" + fname;
    ServerResponse resFile = sendRequest(cmdGetFile);

    if (resFile.status != AppError::SUCCESS) {
        cout << "[ERROR] Khong tim thay file hoac ban khong co quyen: " << resFile.message << endl;
        return;
    }

    // Parse payload để lấy EncryptedKey của chính mình (Owner)
    vector<string> parts = split(resFile.payloadData, '|');
    if (parts.size() < 1) return;
    vector<unsigned char> myEncryptedKey = CryptoUtils::HexToBytes(parts[0]); // Key đang bị khóa bởi PassHash của mình

    // Giải mã ra File Key gốc
    vector<unsigned char> fileKey;
    vector<unsigned char> ivZero(16, 0);
    try {
        // Dùng PassHash hiện tại để mở khóa
        vector<unsigned char> myKek = CryptoUtils::HexToBytes(currentPassHashHex);
        fileKey = CryptoUtils::DecryptAES(myEncryptedKey, myKek, ivZero);
        cout << "[INFO] Da giai ma File Key thanh cong.\n";
    }
    catch (...) {
        cout << "[ERROR] Giai ma File Key that bai! (Co the mat khau sai hoac du lieu loi)\n";
        return;
    }


    // --- GIAI ĐOẠN 3: MÃ HÓA LẠI CHO NGƯỜI NHẬN ---

    cout << "[3/4] Dang ma hoa File Key cho " << targetUser << "...\n";
    // Dùng kekTarget (Shared Secret) để khóa FileKey lại
    vector<unsigned char> keyForTarget = CryptoUtils::EncryptAES(fileKey, kekTarget, ivZero);


    // --- GIAI ĐOẠN 4: GỬI LÊN SERVER ---

    cout << "[4/4] Dang gui lenh Share...\n";
    string cmdShare = "SHARE|" + sessionToken + "|" + fname + "|" + targetUser + "|"
        + to_string(mins) + "|" + CryptoUtils::BytesToHex(keyForTarget);

    ServerResponse resShare = sendRequest(cmdShare);

    if (resShare.status == AppError::SUCCESS) {
        cout << "[SUCCESS] " << resShare.message << endl;
    }
    else {
        cout << "[ERROR] Server tu choi: " << resShare.message << endl;
    }
}

// Yêu cầu hủy share
void ClientCore::actionRevokeShare() {
    if (!isLoggedIn()) {
        cout << "Vui long dang nhap truoc!" << endl;
        return;
    }

    string fname, target;
    cout << "\n--- HUY CHIA SE (REVOKE ACCESS) ---\n";
    cout << "Ten file: "; cin >> fname;
    cout << "Nguoi bi huy quyen (Username): "; cin >> target;

    // Gửi lệnh UNSHARE
    string cmd = "UNSHARE|" + sessionToken + "|" + fname + "|" + target;
    ServerResponse res = sendRequest(cmd);

    if (res.status == AppError::SUCCESS) {
        cout << "[SUCCESS] " + res.message << endl;
        return;
    }
    else {
        cout << "[FAIL] " + res.message << endl;;
    }
}

// Tải file
void ClientCore::actionDownload() {
    if (!isLoggedIn()) { cout << "Vui long login!\n"; return; }

    string fname;
    cout << "\n--- DOWNLOAD (MY FILES) ---\n";
    cout << "Ten file (chi tai duoc file ban so huu): "; cin >> fname;

    // 1. Gửi Request
    string cmd = "DOWNLOAD|" + sessionToken + "|" + fname;
    ServerResponse res = sendRequest(cmd);

    if (res.status != AppError::SUCCESS) {
        cout << "Loi tu Server: " << res.message << endl;
        return;
    }

    // 2. Parse Payload
    // Payload format: EncryptedKeyHex|EncryptedDataHex
    vector<string> parts = split(res.payloadData, '|');
    if (parts.size() < 2) {
        cout << "[ERROR] Loi Protocol: Payload thieu du lieu.\n";
        return;
    }

    vector<unsigned char> encryptedKey = CryptoUtils::HexToBytes(parts[0]);
    vector<unsigned char> encryptedContent = CryptoUtils::HexToBytes(parts[1]);

    // Tách IV
    if (encryptedContent.size() < 16) { cout << "File loi/rong.\n"; return; }
    vector<unsigned char> fileIV(encryptedContent.begin(), encryptedContent.begin() + 16);
    vector<unsigned char> cipherBody(encryptedContent.begin() + 16, encryptedContent.end());

    // 3. Giải mã Key
    vector<unsigned char> fileKey;
    vector<unsigned char> ivZero(16, 0);

    try {
        // Lấy hash mật khẩu hiện tại làm Key để mở khóa FileKey
        vector<unsigned char> kekOwner = CryptoUtils::HexToBytes(currentPassHashHex);

        // Nếu decrypt thất bại (do sai key)
        fileKey = CryptoUtils::DecryptAES(encryptedKey, kekOwner, ivZero);

        cout << "[INFO] Xac thuc chu so huu thanh cong. Dang giai ma...\n";
    }
    catch (...) {
        // Nếu lỗi ở đây, nghĩa là Key này không được mã hóa bằng mật khẩu của người dùng hiện tại
        cout << "[ERROR] Giai ma that bai! Day khong phai file cua ban hoac file duoc share.\n";
        cout << "HINT: Neu day la file duoc share, vui long dung chuc nang 'Download via Link'!\n";
        return;
    }

    // Có FileKey rồi -> Giải mã File và Lưu
    try {
        vector<unsigned char> plainData = CryptoUtils::DecryptAES(cipherBody, fileKey, fileIV);

        string saveDir = CLIENT_STORAGE_ROOT + this->currentUsername + "/";
        if (!fs::exists(saveDir)) {
            fs::create_directories(saveDir);
        }
        string savePath = saveDir + fname;

        writeFile(savePath, plainData);
        cout << "[SUCCESS] File da tai xuong tai: " << savePath << endl;
    }
    catch (exception& e) {
        cout << "[ERROR] Loi giai ma noi dung file: " << e.what() << endl;
    }
}

string parseUrlToken(string url) {
    string prefix = "securenote://download/";
    if (url.find(prefix) != 0) return ""; // Không đúng format
    return url.substr(prefix.length());
}

void ClientCore::actionDownloadViaLink() {
    if (!isLoggedIn()) {
        cout << "Vui long dang nhap truoc!";
        return;
    }

    string url;
    cout << "\n--- DOWNLOAD VIA LINK ---\n";
    cout << "Nhap Link (securenote://download/...): ";
    cin >> url;

    string urlToken = parseUrlToken(url);
    if (urlToken.empty()) {
        cout << "[ERROR] Link khong dung dinh dang!" << endl;
        return;
    }

    // Gửi lệnh
    string cmd = "DOWNLOAD_LINK|" + sessionToken + "|" + urlToken;
    ServerResponse res = sendRequest(cmd);

    if (res.status != AppError::SUCCESS) {
        cout << "[ERROR] " + res.message;
        return;
    }

    // Parse Payload: FILENAME|KEY|DATA
    vector<string> parts = split(res.payloadData, '|');


    size_t firstSep = res.payloadData.find('|');
    if (firstSep == string::npos) {
        cout << "[ERROR] Payload loi (thieu key)" << endl;
        return;
    }

    string fname = res.payloadData.substr(0, firstSep);

    size_t secondSep = res.payloadData.find('|', firstSep + 1);
    if (secondSep == string::npos) {
        cout << "[ERROR] Payload loi (thieu data)" << endl;
        return;
    }

    string encryptedKeyHex = res.payloadData.substr(firstSep + 1, secondSep - firstSep - 1);
    string encryptedDataHex = res.payloadData.substr(secondSep + 1);

    // --- ĐOẠN DƯỚI ĐÂY GIỐNG HỆT actionDownload CŨ ---
    vector<unsigned char> encryptedKey = CryptoUtils::HexToBytes(encryptedKeyHex);
    vector<unsigned char> encryptedContent = CryptoUtils::HexToBytes(encryptedDataHex);

    if (encryptedContent.size() < 16) {
        cout << "[ERROR] Data hong." << endl;
        return;
    }
    vector<unsigned char> fileIV(encryptedContent.begin(), encryptedContent.begin() + 16);
    vector<unsigned char> cipherBody(encryptedContent.begin() + 16, encryptedContent.end());

    // Giải mã Key (Chắc chắn là Shared Secret vì đây là Link Share)
    // Nhưng ta không biết ai gửi? 
    // -> À, vấn đề nảy sinh: Để tính Shared Secret, Bob cần biết Alice là ai để lấy Public Key.
    // -> ServerCore nên trả về thêm "SenderUsername" trong payload nữa, hoặc Client phải tự hỏi.

    // ĐỂ ĐƠN GIẢN: Ta sẽ thử giải mã bằng PassHash (nếu tự share cho mình).
    // Nếu không được, ta sẽ yêu cầu User nhập tên người gửi.

    vector<unsigned char> fileKey;
    vector<unsigned char> ivZero(16, 0);

    // Thử Key Wrapping (PassHash)
    try {
        vector<unsigned char> kekOwner = CryptoUtils::HexToBytes(currentPassHashHex);
        fileKey = CryptoUtils::DecryptAES(encryptedKey, kekOwner, ivZero);
    }
    catch (...) {
        // Nếu không phải chính chủ, hỏi user ai gửi link này
        cout << "[INFO] Link nay do nguoi khac gui. Hay nhap Username nguoi gui (de lay Public Key): ";
        string senderName;
        cin >> senderName;

        // (Đoạn lấy PubKey và tính Secret giống hệt actionDownload cũ)
        string cmdKey = "GETKEY|" + sessionToken + "|" + senderName;
        ServerResponse resKey = sendRequest(cmdKey);
        if (resKey.status != AppError::SUCCESS) {
            cout << "[ERROR] Khong tim thay user " + senderName << endl;
            return;
        }

        string senderPubPEM = string((const char*)CryptoUtils::HexToBytes(resKey.payloadData).data());
        auto secret = CryptoUtils::ComputeSharedSecret(myPrivateKey, senderPubPEM);
        string secretHex = CryptoUtils::BytesToHex(secret);
        string kekHex = CryptoUtils::HashPassword(secretHex, "common_salt");
        vector<unsigned char> kekShare = CryptoUtils::HexToBytes(kekHex);

        try {
            fileKey = CryptoUtils::DecryptAES(encryptedKey, kekShare, ivZero);
        }
        catch (...) {
            cout << "[ERROR] Giai ma Key that bai. Sai nguoi gui hoac Link hong." << endl;
        }
    }

    // Giải mã file
    try {
        vector<unsigned char> plainData = CryptoUtils::DecryptAES(cipherBody, fileKey, fileIV);
        string saveDir = CLIENT_STORAGE_ROOT + this->currentUsername + "/";
        if (!fs::exists(saveDir)) {
            fs::create_directories(saveDir);
        }
        string savePath = CLIENT_STORAGE_ROOT + this->currentUsername + "/" + fname;
        writeFile(savePath, plainData);
        cout << "[SUCCESS] File da tai xuong tai: " << savePath << endl;
    }
    catch (exception& e) {
        cout << "[ERROR] Decrypt AES: " << e.what();
    }
}

void ClientCore::actionLogout() {
    if (!isLoggedIn()) {
        cout << "Ban chua dang nhap!\n";
        return;
    }

    // Gửi lệnh báo Server hủy Token
    // Giao thức: LOGOUT|token
    string cmd = "LOGOUT|" + sessionToken;
    sendRequest(cmd);

    // Xóa sạch dữ liệu phiên làm việc cục bộ
    sessionToken = "";
    currentUsername = "";
    currentPassHashHex = "";
    myPrivateKey = "";

    cout << "[SUCCESS] Da dang xuat thanh cong.\n";
}

void ClientCore::actionListFiles() {
    if (!isLoggedIn()) {
        cout << "Vui long dang nhap truoc!";
        return;
    }

    // Gửi lệnh
    string cmd = "LIST|" + sessionToken;
    ServerResponse res = sendRequest(cmd);

    if (res.status != AppError::SUCCESS) {
        cout << "[ERROR] " + res.message;
        return;
    }

    // Parse JSON payload
    try {
        json jFiles = json::parse(res.payloadData);

        cout << "\n--- DANH SACH FILE CUA BAN ---\n";
        if (jFiles.empty()) {
            cout << "(Trong)\n";
        }
        else {
            int i = 1;
            for (const auto& file : jFiles) {
                cout << i++ << ". " << file.get<string>() << endl;
            }
        }
        cout << "------------------------------\n";

        cout << "[SUCCESS] Da lay danh sach file." << endl;
        return;
    }
    catch (...) {
        cout << "[ERROR] Loi parse du lieu tu Server." << endl;
    }
}

void ClientCore::actionDeleteFile() {
    if (!isLoggedIn()) {
        cout << "Vui long dang nhap truoc!";
        return;
    }

    string fname;
    cout << "\n--- XOA FILE ---\n";
    cout << "Nhap ten file muon xoa: "; cin >> fname;

    // Bước xác nhận (UX)
    char confirm;
    cout << "Ban co chac chan muon xoa vinh vien file '" << fname << "' tren Server? (y/n): ";
    cin >> confirm;

    if (confirm != 'y' && confirm != 'Y') {
        cout << "Da huy thao tac xoa." << endl;
        return;
    }

    // Gửi lệnh
    string cmd = "DELETE|" + sessionToken + "|" + fname;
    ServerResponse res = sendRequest(cmd);

    if (res.status == AppError::SUCCESS) {
        cout << "[SUCCESS] " + res.message << endl;
        return;
    }
    else {
        cout << "[FAIL] " + res.message << endl;
    }
}