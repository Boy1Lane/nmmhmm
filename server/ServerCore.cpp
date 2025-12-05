#include "ServerCore.h"
#include "../common/CryptoUtils.h"
#include <iostream>
#include "../common/json.hpp"

using json = nlohmann::json;

ServerCore::ServerCore(const std::string& storageDir,
    const std::string& userPath,
    const std::string& metaPath) : userManager(userPath), fileManager(storageDir, metaPath) {}

// Xử lý đăng ký
ServerResponse ServerCore::reqRegister(const std::string& username,
    const std::string& passHashHex,
    const std::string& saltHex,
    const std::string& pubKeyHex)
{
    // Convert Hex -> Bytes để lưu trữ
    std::vector<unsigned char> passHash = CryptoUtils::HexToBytes(passHashHex);
    std::vector<unsigned char> salt = CryptoUtils::HexToBytes(saltHex);
    std::vector<unsigned char> pubKey = CryptoUtils::HexToBytes(pubKeyHex);

    if (userManager.registerUser(username, passHash, salt, pubKey)) {
        return { AppError::SUCCESS, "Dang ky thanh cong!", "" };
    }
    return { AppError::ERR_USER_EXIST, "Tai khoan da ton tai!", "" };
}

// Xử lý đăng nhập
ServerResponse ServerCore::reqLogin(const std::string& username, const std::string& inputHashHex) {
    std::vector<unsigned char> inputHash = CryptoUtils::HexToBytes(inputHashHex);

    std::string token = userManager.login(username, inputHash);
    if (!token.empty()) {
        return { AppError::SUCCESS, "Login OK", token }; // Payload chứa Token
    }
    return { AppError::ERR_AUTH_FAIL, "Sai tai khoan hoac mat khau", "" };
}

// Xử lý update
ServerResponse ServerCore::reqUpload(const std::string& token,
    const std::string& filename,
    const std::vector<unsigned char>& fileData,
    const std::string& ownerEncryptedKey)
{
    // Xác thực Token -> Lấy username
    std::string owner = userManager.validateToken(token);
    if (owner.empty()) return { AppError::ERR_ACCESS_DENIED, "Token khong hop le", "" };

    // Lưu file
    fileManager.saveFile(filename, fileData, owner, ownerEncryptedKey);
    return { AppError::SUCCESS, "Upload thanh cong", "" };
}

// Xử lý share
ServerResponse ServerCore::reqShare(const std::string& token, const std::string& filename, const std::string& targetUser, int durationMinutes, const std::string& encryptedKeyForTarget) {
    string sender = userManager.validateToken(token);
    if (sender.empty()) return { AppError::ERR_ACCESS_DENIED, "Token khong hop le", "" };

    int durationSeconds = durationMinutes * 60;

    // Gọi FileManager lấy Token
    string shareToken = fileManager.shareFile(filename, sender, targetUser, durationSeconds, encryptedKeyForTarget);

    if (!shareToken.empty()) {
        // Tạo URL
        string url = "securenote://download/" + shareToken;
        return { AppError::SUCCESS, "Link chia se: " + url, "" };
    }

    return { AppError::ERR_ACCESS_DENIED, "Loi chia se", "" };
}

// XỬ lý hủy share
ServerResponse ServerCore::reqRevokeShare(const std::string& token, const std::string& filename, const std::string& targetUser) {
    // Xác thực chủ sở hữu (người hủy)
    std::string owner = userManager.validateToken(token);
    if (owner.empty()) return { AppError::ERR_ACCESS_DENIED, "Token khong hop le", "" };

    // Gọi FileManager
    if (fileManager.revokeShare(filename, owner, targetUser)) {
        return { AppError::SUCCESS, "Da huy quyen truy cap cua " + targetUser, "" };
    }

    return { AppError::ERR_FILE_NOT_FOUND, "Loi: File khong ton tai, ban khong phai chu so huu, hoac chua tung share cho nguoi nay.", "" };
}

// Xử lý download
ServerResponse ServerCore::reqDownload(const std::string& token, const std::string& filename) {
    // Xác thực người yêu cầu
    std::string requester = userManager.validateToken(token);
    if (requester.empty()) return { AppError::ERR_ACCESS_DENIED, "Token khong hop le", "" };

    AppError err;
    std::string keyOut;

    // Lấy nội dung file và key
    std::vector<unsigned char> data = fileManager.getFile(filename, requester, err, keyOut);

    if (err != AppError::SUCCESS) {
        if (err == AppError::ERR_LINK_EXPIRED) return { err, "Lien ket da het han!", "" };
        if (err == AppError::ERR_ACCESS_DENIED) return { err, "Ban khong co quyen truy cap file nay", "" };
        return { err, "Khong tim thay file", "" };
    }

    // Đóng gói dữ liệu trả về
    // Format payload: KEY_HEX|DATA_HEX
    std::string payload = keyOut + "|" + CryptoUtils::BytesToHex(data);

    return { AppError::SUCCESS, "Download OK", payload };
}

ServerResponse ServerCore::reqDownloadViaLink(const std::string& token, const std::string& urlToken) {
    string requester = userManager.validateToken(token);
    if (requester.empty()) return { AppError::ERR_ACCESS_DENIED, "Token khong hop le", "" };

    AppError err;
    string keyOut, filenameOut;

    // Gọi hàm mới bên FileManager
    vector<unsigned char> data = fileManager.getFileByLink(urlToken, requester, err, keyOut, filenameOut);

    if (err != AppError::SUCCESS) {
        if (err == AppError::ERR_LINK_EXPIRED) return { err, "Link da het han!", "" };
        if (err == AppError::ERR_ACCESS_DENIED) return { err, "Link nay khong danh cho ban!", "" };
        return { err, "Link khong ton tai", "" };
    }

    // Payload: FILENAME|KEY|DATA (Thêm filename vào đầu để Client biết tên file mà lưu)
    string payload = filenameOut + "|" + keyOut + "|" + CryptoUtils::BytesToHex(data);

    return { AppError::SUCCESS, "Download Link OK", payload };
}

// Lấy public key DH (để share)
ServerResponse ServerCore::reqGetPublicKey(const std::string& token, const std::string& targetUser) {
    // Xác thực người hỏi
    if (userManager.validateToken(token).empty())
        return { AppError::ERR_ACCESS_DENIED, "Token khong hop le", "" };

    // Lấy key
    std::vector<unsigned char> pubKey = userManager.getPublicKey(targetUser);
    if (pubKey.empty()) {
        return { AppError::ERR_FILE_NOT_FOUND, "User khong ton tai", "" };
    }

    // Trả về key dạng Hex để Client convert lại
    return { AppError::SUCCESS, "OK", CryptoUtils::BytesToHex(pubKey) };
}

ServerResponse ServerCore::reqGetSalt(const std::string& username) {
    string saltHex = userManager.getSalt(username);
    if (saltHex.empty()) {
        return { AppError::ERR_AUTH_FAIL, "User khong ton tai", "" };
    }
    return { AppError::SUCCESS, "OK", saltHex };
}

ServerResponse ServerCore::reqLogout(const std::string& token) {
    userManager.logout(token);
    return { AppError::SUCCESS, "Logged out", "" };
}

ServerResponse ServerCore::reqListFiles(const std::string& token) {
    // Xác thực
    std::string user = userManager.validateToken(token);
    if (user.empty()) return { AppError::ERR_ACCESS_DENIED, "Token khong hop le", "" };

    // Lấy danh sách file
    std::vector<std::string> files = fileManager.listFiles(user);

    // Đóng gói thành JSON string để gửi về
    if (files.empty()) {
        return { AppError::SUCCESS, "Ban chua upload file nao.", "[]" };
    }

    json j = files; // nlohmann::json tự động convert vector -> json array
    return { AppError::SUCCESS, "Danh sach file cua ban", j.dump() };
}

ServerResponse ServerCore::reqDeleteFile(const std::string& token, const std::string& filename) {
    // Xác thực user
    std::string user = userManager.validateToken(token);
    if (user.empty()) return { AppError::ERR_ACCESS_DENIED, "Token khong hop le", "" };

    // Gọi FileManager xóa
    if (fileManager.deleteFile(filename, user)) {
        return { AppError::SUCCESS, "Da xoa file '" + filename + "' thanh cong.", "" };
    }

    return { AppError::ERR_ACCESS_DENIED, "Xoa that bai (File khong ton tai hoac ban khong phai chu so huu)", "" };
}