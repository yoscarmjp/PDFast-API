#include "../csrf_tokens.h"
#include "../token_encryption.h"
#include "../env_loader.h"
#include <string>
#include <optional>
#include <random>

std::unordered_map<std::string, std::string> ENV = load_env_file(".env");
sw::redis::Redis redis(ENV["REDIS_URL"]);

std::string generate_csrf_token() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dist(33, 126);
    std::string token;

    for (int i = 0; i < 32; i++)
        token += static_cast<char>(dist(gen));

    return token;
}

bool validate_csrf_token(const std::string& csrf_token, const std::string& session_id) {
    const char* salt = std::getenv("ENCRYPTION_KEY");
    const char* rounds_str = std::getenv("ENCRYPTION_ROUNDS");
    if (!salt || !rounds_str || csrf_token.empty() || session_id.empty()) return false;

    int rounds = std::stoi(rounds_str);
    std::string encrypted_csrf_token = encrypt_token(csrf_token, salt, rounds);
    std::string encrypted_session_id = encrypt_token(session_id, salt, rounds);

    std::optional<std::string> csrf_token_from_redis = redis.get("csrf_token:" + encrypted_session_id);

    std::cout << "NEW CSRF TOKEN GENERATED TO EXPIRE IN 60 SECONDS" << std::endl;

    return csrf_token_from_redis && *csrf_token_from_redis == encrypted_csrf_token;
}

