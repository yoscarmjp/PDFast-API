#include <random>
#include "../csrf_tokens.h"

std::string generate_csrf_token() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dist(33, 126);
    std::string token;

    for (int i = 0; i < 32; i++)
        token += static_cast<char>(dist(gen));

    return token;
}