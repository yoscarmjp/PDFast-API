#include <openssl/evp.h>
#include <openssl/rand.h>
#include <vector>
#include <sstream>

std::string toHex(const std::vector<unsigned char>& data) {
    static const char hex_chars[] = "0123456789abcdef";
    std::string result;
    result.reserve(data.size() * 2);
    
    for (unsigned char byte : data) {
        result += hex_chars[(byte >> 4) & 0x0F];
        result += hex_chars[byte & 0x0F];
    }
    
    return result;
}

// Versión segura de fromHex
std::vector<unsigned char> fromHex(const std::string& hex) {
    std::vector<unsigned char> data;
    data.reserve(hex.length() / 2);
    
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        char byte = static_cast<char>(strtol(byteString.c_str(), nullptr, 16));
        data.push_back(byte);
    }
    
    return data;
}

std::string encrypt_token(const std::string& token, const std::string& key, int rounds) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char iv[EVP_MAX_IV_LENGTH] = {0};
    std::string current_token = token;

    for (int i = 0; i < rounds; ++i) {
        std::vector<unsigned char> ciphertext(token.size() + EVP_MAX_BLOCK_LENGTH);
        int len;
        
        EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, 
                          reinterpret_cast<const unsigned char*>(key.c_str()), iv);
        EVP_EncryptUpdate(ctx, ciphertext.data(), &len, 
                         reinterpret_cast<const unsigned char*>(current_token.c_str()), 
                         current_token.size());
        int final_len;
        EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &final_len);
        
        current_token = toHex(std::vector<unsigned char>(
            ciphertext.begin(), ciphertext.begin() + len + final_len));
    }

    EVP_CIPHER_CTX_free(ctx);
    return current_token;
}

std::string decrypt_token(const std::string& encrypted_token, const std::string& key, int rounds) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char iv[EVP_MAX_IV_LENGTH] = {0};
    std::string current_token = encrypted_token;

    for (int i = 0; i < rounds; ++i) {
        std::vector<unsigned char> cipher_bytes = fromHex(current_token);
        std::vector<unsigned char> decrypted(cipher_bytes.size() + EVP_MAX_BLOCK_LENGTH);
        int len;
        
        EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, 
                          reinterpret_cast<const unsigned char*>(key.c_str()), iv);
        EVP_DecryptUpdate(ctx, decrypted.data(), &len, 
                         cipher_bytes.data(), cipher_bytes.size());
        int final_len;
        EVP_DecryptFinal_ex(ctx, decrypted.data() + len, &final_len);
        
        current_token = std::string(decrypted.begin(), 
                                  decrypted.begin() + len + final_len);
    }

    EVP_CIPHER_CTX_free(ctx);
    return current_token;
}