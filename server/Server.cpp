#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <thread>
#include <iostream>
#include <sstream>
#include <mutex>
#include <filesystem>
#include <fstream>

#include "ServerCore.h"
#include "../common/CryptoUtils.h"
#include "../common/json.hpp"

// Link với thư viện Winsock của Windows
#pragma comment (lib, "Ws2_32.lib")

using namespace std;
using json = nlohmann::json;
namespace fs = std::filesystem;

struct ServerConfig {
    int port;
    string storageDir;
    string userPath;
    string metaPath;
};

// --- CẤU HÌNH SERVER ---
#define DEFAULT_PORT 8080
#define BUFFER_SIZE 1024 * 1024 // Buffer 1MB

// --- BIẾN TOÀN CỤC (GLOBAL) ---
ServerCore* g_ServerApp = nullptr;
std::mutex appMutex; // Khóa bảo vệ

// Hàm đọc config
ServerConfig loadConfig(const string& configPath) {
    ifstream f(configPath);
    if (!f.is_open()) {
        cerr << "[WARN] Khong tim thay config.json! Su dung mac dinh.\n";
        return { 8080, "../data/storage/", "../data/users.json", "../data/metadata.json" };
    }

    json j;
    f >> j;

    return {
        j.value("server_port", 8080),
        j.value("storage_dir", "../data/storage"),
        j.value("db_user_path", "../data/users.json"),
        j.value("db_meta_path", "../data/metadata.json")
    };
}

// Hàm tách chuỗi
vector<string> split(const string& s, char delimiter) {
    vector<string> tokens;
    string token;
    istringstream tokenStream(s);
    while (getline(tokenStream, token, delimiter)) {
        tokens.push_back(token);
    }
    return tokens;
}

// --- XỬ LÝ TỪNG CLIENT ---
void ClientHandler(SOCKET clientSocket) {
    cout << "[THREAD] Client connected on socket: " << clientSocket << endl;

    char* buffer = new char[BUFFER_SIZE];

    while (true) {
        memset(buffer, 0, BUFFER_SIZE);
        int bytesReceived = recv(clientSocket, buffer, BUFFER_SIZE, 0);

        if (bytesReceived <= 0) {
            cout << "[THREAD] Client disconnected (Socket " << clientSocket << ")\n";
            break;
        }

        string requestRaw(buffer);
        if (!requestRaw.empty() && requestRaw.back() == '\n') requestRaw.pop_back();

        // Log lệnh ngắn gọn (tránh in cả file hex dài)
        string logMsg = requestRaw.size() > 50 ? requestRaw.substr(0, 50) + "..." : requestRaw;
        cout << "[RECV] " << logMsg << endl;

        vector<string> args = split(requestRaw, '|');
        if (args.empty()) continue;

        string cmd = args[0];
        ServerResponse res = { AppError::ERR_NETWORK, "Unknown Command", "" };

        // Dùng Mutex khóa lại khi gọi vào ServerCore
        {
            lock_guard<mutex> lock(appMutex);

            try {
                if (g_ServerApp == nullptr) {
                    res.message = "Server Core not initialized!";
                }
                else if (cmd == "REGISTER" && args.size() == 5) {
                    res = g_ServerApp->reqRegister(args[1], args[2], args[3], args[4]);
                }
                else if (cmd == "LOGIN" && args.size() == 3) {
                    res = g_ServerApp->reqLogin(args[1], args[2]);
                }
                else if (cmd == "UPLOAD" && args.size() == 5) {
                    // UPLOAD|token|filename|hexData|hexKey
                    vector<unsigned char> fileBytes = CryptoUtils::HexToBytes(args[3]);
                    res = g_ServerApp->reqUpload(args[1], args[2], fileBytes, args[4]);
                }
                else if (cmd == "GETKEY" && args.size() == 3) {
                    res = g_ServerApp->reqGetPublicKey(args[1], args[2]);
                }
                else if (cmd == "SHARE" && args.size() == 6) {
                    int mins = stoi(args[4]);
                    res = g_ServerApp->reqShare(args[1], args[2], args[3], mins, args[5]);
                }
                else if (cmd == "UNSHARE" && args.size() == 4) {
                    // UNSHARE|token|filename|targetUser
                    res = g_ServerApp->reqRevokeShare(args[1], args[2], args[3]);
                }
                else if (cmd == "DOWNLOAD" && args.size() == 3) {
                    res = g_ServerApp->reqDownload(args[1], args[2]);
                }
                else if (cmd == "DOWNLOAD_LINK" && args.size() == 3) {
                    // DOWNLOAD_LINK|sessionToken|urlToken
                    res = g_ServerApp->reqDownloadViaLink(args[1], args[2]);
                }
                else if (cmd == "GETSALT" && args.size() == 2) {
                    // GETSALT|username
                    res = g_ServerApp->reqGetSalt(args[1]);
                }
                else if (cmd == "LOGOUT" && args.size() == 2) {
                    // LOGOUT|token
                    res = g_ServerApp->reqLogout(args[1]);
                }
                else if (cmd == "LIST" && args.size() == 2) {
                    // LIST|token
                    res = g_ServerApp->reqListFiles(args[1]);
                }
                else if (cmd == "DELETE" && args.size() == 3) {
                    // DELETE|token|filename
                    res = g_ServerApp->reqDeleteFile(args[1], args[2]);
                }
                else {
                    res.message = "Invalid Command Format or Wrong Argument Count";
                }
            }
            catch (const std::exception& e) {
                res.status = AppError::ERR_CRYPTO_FAIL;
                res.message = string("Server Exception: ") + e.what();
                cerr << "[ERROR] " << e.what() << endl;
            }
        }

        // Phản hồi cho Client
        string responseStr = to_string((int)res.status) + "|" + res.message + "|" + res.payloadData + "\n";

        send(clientSocket, responseStr.c_str(), (int)responseStr.size(), 0);
    }

    delete[] buffer;
    closesocket(clientSocket);
}

void SetupEnvironment(const ServerConfig& cfg) {
    if (!fs::exists(cfg.storageDir)) {
        fs::create_directories(cfg.storageDir);
        cout << "[INIT] Created storage directory: " << cfg.storageDir << endl;
    }

    // Tạo thư mục cha cho file json nếu cần
    fs::path pUser(cfg.userPath);
    if (pUser.has_parent_path() && !fs::exists(pUser.parent_path())) {
        fs::create_directories(pUser.parent_path());
    }

    if (!fs::exists(cfg.userPath)) {
        ofstream f(cfg.userPath); f << "{}";
        cout << "[INIT] Created user DB: " << cfg.userPath << endl;
    }

    if (!fs::exists(cfg.metaPath)) {
        ofstream f(cfg.metaPath); f << "{}";
        cout << "[INIT] Created metadata DB: " << cfg.metaPath << endl;
    }
}

int main() {
    // 1. Load Config & Setup
    ServerConfig cfg = loadConfig("../serverconfig.json");
    SetupEnvironment(cfg);

    // 2. Khởi tạo Global Server Core (Quan trọng)
    g_ServerApp = new ServerCore(cfg.storageDir, cfg.userPath, cfg.metaPath);

    // 3. Khởi tạo Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        cerr << "WSAStartup failed.\n";
        return 1;
    }

    // 4. Tạo Socket
    SOCKET serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == INVALID_SOCKET) {
        cerr << "Can't create socket.\n";
        return 1;
    }

    // 5. Bind
    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(cfg.port);

    if (::bind(serverSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        cerr << "Bind failed. Port " << cfg.port << " busy?\n";
        return 1;
    }

    // 6. Listen
    if (listen(serverSocket, SOMAXCONN) == SOCKET_ERROR) {
        cerr << "Listen failed.\n";
        return 1;
    }

    cout << "=== SECURE SERVER RUNNING ON PORT " << cfg.port << " ===\n";
    cout << "Waiting for connections...\n";

    // 7. Accept Loop
    while (true) {
        sockaddr_in clientAddr;
        int clientAddrSize = sizeof(clientAddr);
        SOCKET clientSocket = accept(serverSocket, (sockaddr*)&clientAddr, &clientAddrSize);

        if (clientSocket == INVALID_SOCKET) {
            cerr << "Accept failed.\n";
            continue;
        }

        // Lấy IP Client
        char clientIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(clientAddr.sin_addr), clientIP, INET_ADDRSTRLEN);
        cout << "[CONNECTION] Client from: " << clientIP << endl;

        // Tạo luồng (Thread)
        thread t(ClientHandler, clientSocket);
        t.detach();
    }

    delete g_ServerApp;
    closesocket(serverSocket);
    WSACleanup();
    return 0;
}