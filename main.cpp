#include "crow.h"
#include "./src/env_loader.h"
#include "./src/csrf_tokens.h"
#include "./src/token_encryption.h"
#include <sw/redis++/redis++.h>
#include <fstream>
#include <sstream>
#include <iostream>
#include <filesystem>
#include <string>
#include <map>
#include <unordered_map>

std::unordered_map<std::string, std::string> ENV = load_env_file(".env");

using namespace sw::redis;
sw::redis::Redis redis("tcp://redis:6379");

bool validate_csrf_token(const crow::request& req) {
    std::string salt = ENV["ENCRYPTION_KEY"];
    int rounds = std::stoi(ENV["ENCRYPTION_ROUNDS"]);
    std::string session_id = req.get_header_value("session_id");
    std::string csrf_token = req.get_header_value("csrf_token");
    std::string encrypted_csrf_token = encrypt_token(csrf_token, salt, rounds);
    std::string encrypted_session_id = encrypt_token(session_id, salt, rounds);
    if (session_id.empty() || encrypted_csrf_token.empty()) return false;
    std::optional<std::string> csrf_token_from_redis = redis.get("csrf_token:" + encrypted_session_id);
    bool result = csrf_token_from_redis && *csrf_token_from_redis == encrypted_csrf_token;
    return csrf_token_from_redis && *csrf_token_from_redis == encrypted_csrf_token;
}



int main() {
    crow::SimpleApp app;

    // ----------------------------------------------------------------  DEBUG ----------------------------------------------------------------
    CROW_ROUTE(app, "/")([]() {
        return "Hello, World!";
    });

    // ----------------------------------------------------------------  GET TOKEN ----------------------------------------------------------------
    CROW_ROUTE(app, "/token")([](crow::response& res) {
        int rounds = std::stoi(ENV["ENCRYPTION_ROUNDS"]);
        std::string salt = ENV["ENCRYPTION_KEY"];
        std::string session_id = generate_csrf_token();
        std::string csrf_token = generate_csrf_token();
        std::string encrypted_csrf_token = encrypt_token(csrf_token, salt, rounds);
        std::string encrypted_session_id = encrypt_token(session_id, salt, rounds);
        
        redis.setex("csrf_token:" + encrypted_session_id, 3600, encrypted_csrf_token);
        
        crow::json::wvalue response;
        response["session_id"] = session_id;
        response["csrf_token"] = csrf_token;

        res.write(response.dump());
        res.end();
    });

    // ----------------------------------------------------------------  GET PDF ----------------------------------------------------------------
    CROW_ROUTE(app, "/PDF/<string>/<string>/<int>")([](const crow::request& req, crow::response& res, std::string username, std::string slug, int chapter) {
        std::stringstream file_path;
        file_path << "PDF/" << username << "/" << slug << "/" << chapter << ".pdf";
        std::cout << file_path.str() << std::endl;
        std::ifstream file(file_path.str(), std::ios::binary);

        if (!file) {
            res.code = 404;
            res.write("404 Not Found");
            res.end();
            return;
        }

        std::stringstream buffer;
        buffer << file.rdbuf();
        res.add_header("Content-Type", "application/pdf");
        res.write(buffer.str());
        res.end();
    });

    // ----------------------------------------------------------------  POST PDF ----------------------------------------------------------------
    CROW_ROUTE(app, "/PDF/<string>/<string>/<int>").methods(crow::HTTPMethod::POST)([](const crow::request& req, crow::response& res, std::string username, std::string slug, int chapter) {
        if (!validate_csrf_token(req)) {
            res.code = 403;
            res.write("403 Forbidden: CSRF token is invalid or missing");
            res.end();
            return;
        }

        std::stringstream dir_path;
        dir_path << "PDF/" << username << "/" << slug;

        std::stringstream file_path;
        file_path << dir_path.str() << "/" << chapter << ".pdf";

        std::filesystem::create_directories(dir_path.str());

        std::ofstream file(file_path.str(), std::ios::binary);
        if (!file) {
            res.code = 500;
            res.write("500 Internal Server Error");
            res.end();
            return;
        }

        file.write(req.body.data(), req.body.size());
        res.code = 201;
        res.write("201 Created");
        res.end();
    });

    app.bindaddr("0.0.0.0").port(8003).multithreaded().run();
}
