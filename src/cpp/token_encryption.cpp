#include "../token_encryption.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <vector>
#include <sstream>
#include <iomanip>

std::string toHex(const std::vector<unsigned char>& data) {
    std::stringstream ss;
    for (unsigned char byte : data)
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
    return ss.str();
}

std::vector<unsigned char> fromHex(const std::string& hex) {
    std::vector<unsigned char> data(hex.length() / 2);
    for (size_t i = 0; i < hex.length(); i += 2)
        data[i / 2] = std::stoi(hex.substr(i, 2), nullptr, 16);
    return data;
}

std::string encrypt_token(const std::string& token, const std::string& key, int rounds) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char iv[EVP_MAX_IV_LENGTH] = {0};

    int len;
    std::vector<unsigned char> ciphertext(token.size() + EVP_MAX_BLOCK_LENGTH);
    std::string current_token = token;

    for (int i = 0; i < rounds; ++i) {
        EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, reinterpret_cast<const unsigned char*>(key.c_str()), iv);
        EVP_EncryptUpdate(ctx, ciphertext.data(), &len, reinterpret_cast<const unsigned char*>(current_token.c_str()), current_token.size());
        EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
        current_token = toHex(std::vector<unsigned char>(ciphertext.begin(), ciphertext.begin() + len));
    }

    EVP_CIPHER_CTX_free(ctx);
    return current_token;
}


std::string decrypt_token(const std::string& encrypted_token, const std::string& key, int rounds) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char iv[EVP_MAX_IV_LENGTH];
    RAND_bytes(iv, sizeof(iv));  

    int len;
    std::vector<unsigned char> decrypted_token(encrypted_token.size());
    std::string current_token = encrypted_token;

    for (int i = 0; i < rounds; ++i) {
        std::vector<unsigned char> cipher_bytes = fromHex(current_token);
        EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, reinterpret_cast<const unsigned char*>(key.c_str()), iv);
        EVP_DecryptUpdate(ctx, decrypted_token.data(), &len, cipher_bytes.data(), cipher_bytes.size());
        EVP_DecryptFinal_ex(ctx, decrypted_token.data() + len, &len);
        current_token = std::string(decrypted_token.begin(), decrypted_token.begin() + len);
    }

    EVP_CIPHER_CTX_free(ctx);
    return current_token;
}
