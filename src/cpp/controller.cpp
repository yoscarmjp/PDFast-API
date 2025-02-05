#include "../controller.h"
#include "../csrf_tokens.h"
#include "../token_encryption.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <filesystem>

bool isCorrectHost(const crow::request& req) {
    return req.get_header_value("Host") == ENV["ALLOWED_HOSTS"];
}

bool isCorrectOrigin(const crow::request& req) {
    return req.get_header_value("Origin") == ENV["CORS_ORIGIN"];
}

bool isCorrectMethod(const crow::request& req) {
    return req.method == "POST"_method || req.method == "GET"_method || req.method == "OPTIONS"_method;
}

void processCodeHTTP(crow::response& res, int code){
    res.code = code;

    switch (code) {
        case 200:
            res.write("200 OK");
            break;
        case 201:
            res.write("201 Created");
            break;
        case 400:
            res.write("400 Bad Request");
            break;
        case 401:
            res.write("401 Unauthorized");
            break;
        case 403:
            res.write("403 Forbidden: Host not allowed");
            break;
        case 405:
            res.write("405 Method Not Allowed");
            break;
        case 404:
            res.write("404 Not Found");
            break;
        case 500:
            res.write("500 Internal Server Error");
            break;
        default:
            res.write("Unknown error");
            break;
    }

    res.end();
}

void setup_routes(crow::App<crow::CORSHandler>& app) {

    // ________________________________________________________________ HELLO WORLD ________________________________________________________________
    CROW_ROUTE(app, "/")([]() {
        return "Hello, World!";
    });

    // ________________________________________________________________ TOKEN ________________________________________________________________

    CROW_ROUTE(app, "/token")([](crow::request& req, crow::response& res) {
        if(!isCorrectHost(req) || !isCorrectOrigin(req)){
            processCodeHTTP(res, 403);
            return;
        }

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

    // ________________________________________________________________ GET PDF ________________________________________________________________

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

    // ________________________________________________________________ POST PDF ________________________________________________________________
    
    CROW_ROUTE(app, "/PDF/<string>/<string>/<int>").methods(crow::HTTPMethod::POST)([](const crow::request& req, crow::response& res, std::string username, std::string slug, int chapter) {
        std::stringstream dir_path, file_path;
        dir_path << "PDF/" << username << "/" << slug;
        file_path << dir_path.str() << "/" << chapter << ".pdf";

        if(!isCorrectHost(req) || !isCorrectOrigin(req))
            processCodeHTTP(res, 403);

        if(!isCorrectMethod(req))
            processCodeHTTP(res, 405);

        if(req.get_header_value("csrf_token").empty() || req.get_header_value("session_id").empty())
            processCodeHTTP(res, 401);

        if(!validate_csrf_token(req.get_header_value("session_id"), req.get_header_value("csrf_token")))
            processCodeHTTP(res, 400);

        std::filesystem::create_directories(dir_path.str());
        std::ofstream file(file_path.str(), std::ios::binary);
        if (!file)
            processCodeHTTP(res, 500);

        file.write(req.body.data(), req.body.size());
        processCodeHTTP(res, 201);
    });
}
