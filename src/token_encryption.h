#ifndef __TOKEN_ENCRYPTION_H__
#define __TOKEN_ENCRYPTION_H__

#include <vector>
#include <string>

/**
* @brief Decrypts a token using the provided key and rounds
* @param encrypted_token The token to decrypt
* @param key The key to use for decryption
* @param rounds The number of rounds to use for decryption
* @return The decrypted token
**/
std::string decrypt_token(const std::string& encrypted_token, const std::string& key, int rounds);

/**
* @brief Encrypts a token using the provided key and rounds
* @param token The token to encrypt
* @param key The key to use for encryption
* @param rounds The number of rounds to use for encryption
* @return The encrypted token
**/
std::string encrypt_token(const std::string& token, const std::string& key, int rounds);

/**
* @brief Converts a vector of bytes to a hex string
* @param data The vector of bytes to convert
* @return The hex string
**/
std::string toHex(const std::vector<unsigned char>& data);

/**
* @brief Converts a hex string to a vector of bytes
* @param hex The hex string to convert
* @return The vector of bytes
**/
std::vector<unsigned char> fromHex(const std::string& hex);

#endif