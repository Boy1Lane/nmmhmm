#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <string>
#include "ClientCore.h"

// Link thư viện Winsock
#pragma comment(lib, "Ws2_32.lib")

using namespace std;

int main() {
    // 1. Khởi tạo Winsock (CHỈ LÀM 1 LẦN DUY NHẤT Ở ĐÂY)
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) return 1;

    SOCKET clientSocket = INVALID_SOCKET;
    sockaddr_in serverAddr;

    // Biến để lưu IP và Port người dùng nhập
    string ipInput;
    int portInput;

    while (true) {
        // --- A. Nhập thông tin ---
        cout << "--------------------------------\n";
        cout << "Nhap IP Server (VD: 192.168.1.10): ";
        cin >> ipInput;
        cout << "Nhap PORT (VD: 8080): ";
        cin >> portInput;

        // --- B. Tạo Socket mới cho mỗi lần thử ---
        clientSocket = socket(AF_INET, SOCK_STREAM, 0);
        if (clientSocket == INVALID_SOCKET) {
            cerr << "Loi tao socket!\n";
            WSACleanup();
            return 1;
        }

        // --- C. Cấu hình địa chỉ ---
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_addr.s_addr = inet_addr(ipInput.c_str());
        serverAddr.sin_port = htons(portInput);

        // --- D. Thử kết nối ---
        cout << "Dang ket noi toi " << ipInput << ":" << portInput << "...\n";
        if (connect(clientSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == 0) {
            cout << ">>> Ket noi thanh cong! <<<\n";
            break; // Thoát vòng lặp nếu thành công
        }
        else {
            cerr << "[ERROR] Ket noi that bai! Vui long kiem tra IP/Port hoac Firewall Server.\n";
            closesocket(clientSocket); // Đóng socket lỗi để tạo cái mới ở vòng lặp sau
            // KHÔNG ĐƯỢC GỌI WSACleanup() Ở ĐÂY
        }
    }

    // 4. Khởi tạo Logic Client
    ClientCore app(clientSocket);

    // 5. Menu chính
    int choice;
    while (true) {
        cout << "\n=== SECURE FILE CLIENT ===\n";
        if (app.isLoggedIn()) {
            cout << "Trang thai: DA DANG NHAP\n";
            cout << "3. Upload File (Secure)\n";
            cout << "4. Share File (E2EE)\n";
            cout << "5. Download File\n";
            cout << "6. Dang xuat\n";
        }
        else {
            cout << "Trang thai: CHUA DANG NHAP\n";
            cout << "1. Dang ky tai khoan moi\n";
            cout << "2. Dang nhap\n";
        }
        cout << "0. Thoat\n";
        cout << "Lua chon: ";
        cin >> choice;

        if (choice == 0) break;

        try {
            switch (choice) {
            case 1:
                app.actionRegister();
                break;
            case 2:
                app.actionLogin();
                break;
            case 3:
                app.actionUpload();
                break;
            case 4:
                app.actionShare();
                break;
            case 5:
                app.actionDownload();
                break;
            case 6:
                app.actionLogout();
                break;
            default:
                cout << "Lua chon khong hop le.\n";
            }
        }
        catch (const exception& e) {
            cout << "[EXCEPTION] " << e.what() << endl;
        }
    }

    // 6. Dọn dẹp
    closesocket(clientSocket);
    WSACleanup();
    return 0;
}