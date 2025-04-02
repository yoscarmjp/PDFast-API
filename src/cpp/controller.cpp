#include "../controller.h"
#include "../csrf_tokens.h"
#include "../token_encryption.h"
#include <fstream>
#include <sstream>
#include <filesystem>

static const std::unordered_map<int, std::string> messages = {
    {200, "200 OK"}, 
    {201, "201 Created"}, 
    {400, "400 Bad Request"},
    {401, "401 Unauthorized"}, 
    {403, "403 Forbidden: Host not allowed"},
    {404, "404 Not Found"}, 
    {500, "500 Internal Server Error"}
};


// ╭───────────────────────╮
// │      Error            │
// │      Handling         │
// ╰───────────────────────╯

// HOST
bool isCorrectHost(const crow::request& req) {
    return req.get_header_value("Host") == ENV["ALLOWED_HOSTS"];
}

// ORIGIN
bool isCorrectOrigin(const crow::request& req) {
    return req.get_header_value("Origin") == ENV["CORS_ORIGIN"];
}

// METHOD
bool isCorrectMethod(const crow::request& req) {
    return req.method == "POST"_method || req.method == "GET"_method || req.method == "OPTIONS"_method;
}

// WRITE Codes
void processCodeHTTP(crow::response& res, int code) {    
    res.code = code;
    res.write(messages.contains(code) ? messages.at(code) : "Unknown error");
    res.end();
}

// CORS headers
bool validateRequest(const crow::request& req, crow::response& res) {
    if (!isCorrectHost(req) || !isCorrectOrigin(req)) {
        processCodeHTTP(res, 403);
        return false;
    }
    return true;
}

// CSRF token validation
bool validateCSRF(const crow::request& req, crow::response& res) {
    std::string session_id = req.get_header_value("X-Session-ID");
    std::string csrf_token = req.get_header_value("X-CSRF-Token");
    if (session_id.empty() || csrf_token.empty()) {
        processCodeHTTP(res, 400);
        return false;
    }
    std::string salt = ENV["ENCRYPTION_KEY"];
    int rounds = std::stoi(ENV["ENCRYPTION_ROUNDS"]);
    std::string encrypted_session_id = encrypt_token(session_id, salt, rounds);
    if (redis.get("csrf_token:" + encrypted_session_id) != encrypt_token(csrf_token, salt, rounds)) {
        processCodeHTTP(res, 401);
        return false;
    }
    return true;
}

// ╭───────────────────────╮
// │      File             │
// │      Manipulation     │
// ╰───────────────────────╯
// READ
void handleFileRead(crow::response& res, const std::string& path, const std::string& mime) {
    if (!std::filesystem::exists(path)) {
        processCodeHTTP(res, 404);
        return;
    }
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        processCodeHTTP(res, 500);
        return;
    }
    res.add_header("Content-Type", mime);
    const size_t buffer_size = 8192;
    char buffer[buffer_size];
    while (file.read(buffer, buffer_size) || file.gcount() > 0)
        res.write(std::string(buffer, file.gcount()));
    file.close();
    res.end();
}

// WRITE
void handleFileWrite(crow::response& res, const crow::request& req, const std::string& path) {
    std::filesystem::create_directories(std::filesystem::path(path).parent_path());
    std::ofstream file(path, std::ios::binary);
    if (!file) {
        processCodeHTTP(res, 500);
        return;
    }
    file.write(req.body.data(), req.body.size());
    processCodeHTTP(res, 201);
}

// ╭────────────────────╮
// │      ROUTING       │
// ╰────────────────────╯
void setup_routes(crow::App<crow::CORSHandler>& app) {
    CROW_ROUTE(app, "/")([] { return "Hello, World!"; });

    // TOKENIZATION
    CROW_ROUTE(app, "/token")([](const crow::request& req, crow::response& res) {
        if (!validateRequest(req, res)) return;
        std::string session_id = generate_csrf_token();
        std::string csrf_token = generate_csrf_token();
        std::string encrypted_csrf_token = encrypt_token(csrf_token, ENV["ENCRYPTION_KEY"], std::stoi(ENV["ENCRYPTION_ROUNDS"]));
        redis.setex("csrf_token:" + encrypt_token(session_id, ENV["ENCRYPTION_KEY"], std::stoi(ENV["ENCRYPTION_ROUNDS"])), 3600, encrypted_csrf_token);
        res.write(crow::json::wvalue({{"session_id", session_id}, {"csrf_token", csrf_token}}).dump());
        res.end();
    });

    // ╭────────────────────╮
    // │     PDF FILES      │
    // ╰────────────────────╯
    // READ PDF
    // https://pdfastapi.bonzzard.com/PDF/<user>/<slug>/<chapter>.pdf
    CROW_ROUTE(app, "/PDF/<string>/<string>/<int>")([](const crow::request& req, crow::response& res, std::string user, std::string slug, int chapter) {
        if (!validateRequest(req, res)) return;
        handleFileRead(res, "PDF/" + user + "/" + slug + "/" + std::to_string(chapter) + ".pdf", "application/pdf");
    });

    // WRITE PDF
    // https://pdfastapi.bonzzard.com/PDF/<user>/<slug>/<chapter>.pdf
    CROW_ROUTE(app, "/PDF/<string>/<string>/<int>").methods(crow::HTTPMethod::POST)([](const crow::request& req, crow::response& res, std::string user, std::string slug, int chapter) {
        if (!validateRequest(req, res) || !validateCSRF(req, res)) return;
        handleFileWrite(res, req, "PDF/" + user + "/" + slug + "/" + std::to_string(chapter) + ".pdf");
    });

    // ╭────────────────────╮
    // │     PICTURES       │
    // ╰────────────────────╯
    // https://pdfastapi.bonzzard.com/Picture/<user>/<slug>/<chapter>.jpg
    CROW_ROUTE(app, "/Picture/<string>/<string>/<int>")([](const crow::request& req, crow::response& res, std::string user, std::string slug, int chapter) {
        if (!validateRequest(req, res)) return;
        handleFileRead(res, "Picture/" + user + "/" + slug + "/" + std::to_string(chapter) + ".jpg", "image/jpeg");
    });

    // https://pdfastapi.bonzzard.com/Picture/<user>/<slug>/<chapter>.jpeg
    CROW_ROUTE(app, "/Picture/<string>/<string>/<int>")([](const crow::request& req, crow::response& res, std::string user, std::string slug, int chapter) {
        if (!validateRequest(req, res)) return;
        handleFileRead(res, "Picture/" + user + "/" + slug + "/" + std::to_string(chapter) + ".jpeg", "image/jpeg");
    });

    // https://pdfastapi.bonzzard.com/Picture/<user>/<slug>/<chapter>.png
    CROW_ROUTE(app, "/Picture/<string>/<string>/<int>")([](const crow::request& req, crow::response& res, std::string user, std::string slug, int chapter) {
        if (!validateRequest(req, res)) return;
        handleFileRead(res, "Picture/" + user + "/" + slug + "/" + std::to_string(chapter) + ".png", "image/png");
    });

    // WRITE PICTURE JPG JPEG PNG
    // https://pdfastapi.bonzzard.com/Picture/<user>/<slug>/<chapter>.jpg
    CROW_ROUTE(app, "/Picture/<string>/<string>/<int>").methods(crow::HTTPMethod::POST)([](const crow::request& req, crow::response& res, std::string user, std::string slug, int chapter) {
        if (!validateRequest(req, res) || !validateCSRF(req, res)) return;
        handleFileWrite(res, req, "Picture/" + user + "/" + slug + "/" + std::to_string(chapter) + ".jpg");
    });

    // https://pdfastapi.bonzzard.com/Picture/<user>/<slug>/<chapter>.jpeg
    CROW_ROUTE(app, "/Picture/<string>/<string>/<int>").methods(crow::HTTPMethod::POST)([](const crow::request& req, crow::response& res, std::string user, std::string slug, int chapter) {
        if (!validateRequest(req, res) || !validateCSRF(req, res)) return;
        handleFileWrite(res, req, "Picture/" + user + "/" + slug + "/" + std::to_string(chapter) + ".jpeg");
    });

    // https://pdfastapi.bonzzard.com/Picture/<user>/<slug>/<chapter>.png
    CROW_ROUTE(app, "/Picture/<string>/<string>/<int>").methods(crow::HTTPMethod::POST)([](const crow::request& req, crow::response& res, std::string user, std::string slug, int chapter) {
        if (!validateRequest(req, res) || !validateCSRF(req, res)) return;
        handleFileWrite(res, req, "Picture/" + user + "/" + slug + "/" + std::to_string(chapter) + ".png");
    });
}
