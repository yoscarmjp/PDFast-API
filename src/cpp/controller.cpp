#include "../controller.h"
#include "../csrf_tokens.h"
#include "../token_encryption.h"
#include "../env_loader.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <filesystem>

extern std::unordered_map<std::string, std::string> ENV;

void setup_routes(crow::SimpleApp& app) {
    CROW_ROUTE(app, "/")([]() {
        return "Hello, World!";
    });

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

    CROW_ROUTE(app, "/PDF/<string>/<string>/<int>")([](const crow::request& req, crow::response& res, std::string username, std::string slug, int chapter) {
        std::stringstream file_path;
        file_path << "PDF/" << username << "/" << slug << "/" << chapter << ".pdf";
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
}
