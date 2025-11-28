#include "SharedDefinitions.h";

class UserManager {
public:
    // Cần lưu thêm PublicKey để phục vụ E2EE
    AppError Register(std::string user, std::string passHash, std::string salt, std::string publicKey);
    std::string Login(std::string user, std::string passHash); // Trả về Session Token
    std::string GetPublicKey(std::string user); // API cho Alice lấy key của Bob
};