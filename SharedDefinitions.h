#pragma once
#include <string>
#include <vector>

// 1. ENUM XỬ LÝ LỖI (Thay thế cho việc trả về true/false vô hồn)
enum class AppError {
    SUCCESS,
    ERR_NETWORK,        // Lỗi kết nối
    ERR_AUTH_FAIL,      // Sai pass/user
    ERR_FILE_NOT_FOUND, // Không tìm thấy file
    ERR_ACCESS_DENIED,  // Không có quyền
    ERR_LINK_EXPIRED,   // Link hết hạn (Quan trọng)
    ERR_CRYPTO_FAIL     // Lỗi mã hóa/giải mã
};

// 2. CẤU TRÚC GÓI TIN TRẢ VỀ TỪ SERVER (Cho Client biết kết quả)
struct ServerResponse {
    AppError status;
    std::string message;         // Thông báo chi tiết (nếu lỗi)
    std::string payloadJson;     // Dữ liệu chính (dạng JSON string)
};