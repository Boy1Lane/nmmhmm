#include "ServerCore.h"
#include "../common/CryptoUtils.h"
#include <iostream>

ServerCore::ServerCore(const std::string& storageDir,
    const std::string& userPath,
    const std::string& metaPath)
    : userManager(userPath),              // Truyền đường dẫn vào UserManager
    fileManager(storageDir, metaPath)   // Truyền đường dẫn vào FileManager
{
}

// --- 1. XỬ LÝ ĐĂNG KÝ ---
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

// --- 2. XỬ LÝ ĐĂNG NHẬP ---
ServerResponse ServerCore::reqLogin(const std::string& username, const std::string& inputHashHex) {
    std::vector<unsigned char> inputHash = CryptoUtils::HexToBytes(inputHashHex);

    std::string token = userManager.login(username, inputHash);
    if (!token.empty()) {
        return { AppError::SUCCESS, "Login OK", token }; // Payload chứa Token
    }
    return { AppError::ERR_AUTH_FAIL, "Sai tai khoan hoac mat khau", "" };
}

// --- 3. XỬ LÝ UPLOAD ---
ServerResponse ServerCore::reqUpload(const std::string& token,
    const std::string& filename,
    const std::vector<unsigned char>& fileData,
    const std::string& ownerEncryptedKey)
{
    // B1: Xác thực Token -> Lấy username
    std::string owner = userManager.validateToken(token);
    if (owner.empty()) return { AppError::ERR_ACCESS_DENIED, "Token khong hop le", "" };

    // B2: Lưu file
    fileManager.saveFile(filename, fileData, owner, ownerEncryptedKey);
    return { AppError::SUCCESS, "Upload thanh cong", "" };
}

// --- 4. XỬ LÝ SHARE ---
ServerResponse ServerCore::reqShare(const std::string& token,
    const std::string& filename,
    const std::string& targetUser,
    int durationMinutes,
    const std::string& encryptedKeyForTarget)
{
    // B1: Xác thực người gửi (sender)
    std::string sender = userManager.validateToken(token);
    if (sender.empty()) return { AppError::ERR_ACCESS_DENIED, "Token khong hop le", "" };

    // B2: Gọi FileManager với thông tin sender
    int durationSeconds = durationMinutes * 60;

    // Truyền thêm 'sender' vào để FileManager kiểm tra quyền chủ sở hữu
    if (fileManager.shareFile(filename, sender, targetUser, durationSeconds, encryptedKeyForTarget)) {
        return { AppError::SUCCESS, "Da chia se cho " + targetUser, "" };
    }

    return { AppError::ERR_ACCESS_DENIED, "Loi chia se (File khong ton tai hoac ban khong phai chu so huu)", "" };
}

// --- 5. XỬ LÝ DOWNLOAD ---
ServerResponse ServerCore::reqDownload(const std::string& token, const std::string& filename) {
    // B1: Xác thực người yêu cầu
    std::string requester = userManager.validateToken(token);
    if (requester.empty()) return { AppError::ERR_ACCESS_DENIED, "Token khong hop le", "" };

    AppError err;
    std::string keyOut;

    // B2: Lấy nội dung file và key (FileManager sẽ tự check hạn giờ)
    std::vector<unsigned char> data = fileManager.getFile(filename, requester, err, keyOut);

    if (err != AppError::SUCCESS) {
        if (err == AppError::ERR_LINK_EXPIRED) return { err, "Lien ket da het han!", "" };
        if (err == AppError::ERR_ACCESS_DENIED) return { err, "Ban khong co quyen truy cap file nay", "" };
        return { err, "Khong tim thay file", "" };
    }

    // B3: Đóng gói dữ liệu trả về
    // Format payload giả định: KEY_HEX|DATA_HEX (Hoặc JSON nếu muốn xịn hơn)
    // Ở đây mình trả về chuỗi Hex để demo
    std::string payload = keyOut + "|" + CryptoUtils::BytesToHex(data);

    return { AppError::SUCCESS, "Download OK", payload };
}

// --- 6. LẤY PUBLIC KEY (Cho luồng Share) ---
ServerResponse ServerCore::reqGetPublicKey(const std::string& token, const std::string& targetUser) {
    // B1: Xác thực người hỏi
    if (userManager.validateToken(token).empty())
        return { AppError::ERR_ACCESS_DENIED, "Token khong hop le", "" };

    // B2: Lấy key
    std::vector<unsigned char> pubKey = userManager.getPublicKey(targetUser);
    if (pubKey.empty()) {
        return { AppError::ERR_FILE_NOT_FOUND, "User khong ton tai", "" };
    }

    // B3: Trả về key dạng Hex để Client convert lại
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