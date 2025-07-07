#include "../controller.h"
#include "../csrf_tokens.h"
#include "../token_encryption.h"
#include <fstream>
#include <filesystem>
#include <unordered_set>
#include <unordered_map>
#include <sw/redis++/redis++.h>

using namespace sw::redis;

// Configuración
static const std::unordered_set<std::string> VALID_EXTENSIONS = {
    "jpg", "jpeg", "png", "webp", "gif", "bmp", "tiff", "mp4"
};

static const std::unordered_map<int, std::string> MESSAGES = {
    {200, "200 OK"}, 
    {201, "201 Created"}, 
    {400, "400 Bad Request"},
    {401, "401 Unauthorized"}, 
    {403, "403 Forbidden: Host not allowed"},
    {404, "404 Not Found"}, 
    {500, "500 Internal Server Error"}
};

// ────────────────────────
//      Helper Functions
// ────────────────────────

bool isCorrectHost(const crow::request& req) {
    return req.get_header_value("Host") == ENV["ALLOWED_HOSTS"];
}

bool isCorrectOrigin(const crow::request& req) {
    return req.get_header_value("Origin") == ENV["CORS_ORIGIN"];
}

void processCodeHTTP(crow::response& res, int code) {    
    res.code = code;
    res.write(MESSAGES.contains(code) ? MESSAGES.at(code) : "Unknown error");
    res.end();
}

bool validateRequest(const crow::request& req, crow::response& res) {
    if (!isCorrectHost(req)) {
        processCodeHTTP(res, 403);
        return false;
    }
    return true;
}

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
    
    // Verificar token CSRF
    auto encrypted_csrf_token = redis.get("csrf_token:" + encrypted_session_id);
    std::string encrypted_input_token = encrypt_token(csrf_token, salt, rounds);
    
    if (!encrypted_csrf_token || *encrypted_csrf_token != encrypted_input_token) {
        std::cout << "CSRF token mismatch." << std::endl;
        std::cout << "Encrypted Session ID: " << encrypted_session_id << std::endl;
        std::cout << "Encrypted CSRF Token: " << encrypted_input_token << std::endl;
        std::cout << "Stored CSRF Token: " << (encrypted_csrf_token ? *encrypted_csrf_token : "null");
        std::cout << std::endl;
        processCodeHTTP(res, 401);
        return false;
    }
    
    // Verificar usos restantes
    auto remaining_uses = redis.get("token_uses:" + encrypted_session_id);
    if (!remaining_uses) {
        std::cout << "Token not found or expired." << std::endl;
        std::cout << "Encrypted Session ID: " << encrypted_session_id << std::endl;
        std::cout << "Encrypted CSRF Token: " << encrypted_input_token << std::endl;
        
        processCodeHTTP(res, 401);
        return false;
    }
    
    int uses = std::stoi(*remaining_uses);
    if (uses <= 0) {
        std::cout << "Token has no remaining uses." << std::endl;
        processCodeHTTP(res, 401);
        return false;
    }
    
    // Decrementar contador de usos
    redis.decr("token_uses:" + encrypted_session_id);
    
    return true;
}

// ────────────────────────
//      File Operations
// ────────────────────────

void handleFileRead(crow::response& res, const std::string& path) {
    if (!std::filesystem::exists(path)) {
        processCodeHTTP(res, 404);
        return;
    }
    
    std::string extension = path.substr(path.find_last_of(".") + 1);
    std::string mime_type = "image/" + (extension == "jpg" ? "jpeg" : extension);
    
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        processCodeHTTP(res, 500);
        return;
    }
    
    res.add_header("Content-Type", mime_type);
    const size_t buffer_size = 8192;
    char buffer[buffer_size];
    
    while (file.read(buffer, buffer_size) || file.gcount() > 0) {
        res.write(std::string(buffer, file.gcount()));
    }
    
    file.close();
    res.end();
}

void handleFileWrite(crow::response& res, const crow::request& req, const std::string& path) {
    try {
        // Crear directorios padres si no existen
        std::filesystem::path file_path(path);
        std::filesystem::path dir_path = file_path.parent_path();
        
        if (!dir_path.empty() && !std::filesystem::exists(dir_path)) {
            if (!std::filesystem::create_directories(dir_path)) {
                processCodeHTTP(res, 500);
                return;
            }
        }

        // Escribir archivo
        std::ofstream file(file_path, std::ios::binary);
        if (!file.is_open()) {
            processCodeHTTP(res, 500);
            return;
        }
        
        file.write(req.body.data(), req.body.size());
        file.close();

        // Verificar integridad del archivo
        if (!std::filesystem::exists(file_path) || 
            std::filesystem::file_size(file_path) != req.body.size()) {
            std::filesystem::remove(file_path);
            processCodeHTTP(res, 500);
            return;
        }

        processCodeHTTP(res, 201);
    } 
    catch (const std::exception& e) {
        // Loggear el error si es necesario
        processCodeHTTP(res, 500);
    }
}

// ────────────────────────
//      Route Handlers
// ────────────────────────

void setup_routes(crow::App<crow::CORSHandler>& app) {
    CROW_ROUTE(app, "/token/<int>")
    .methods("GET"_method)([](const crow::request& req, crow::response& res, int max_uses) {
        if (!validateRequest(req, res)) return;
        std::string session_id = generate_csrf_token();
        std::string csrf_token = generate_csrf_token();
        std::string encrypted_csrf_token = encrypt_token(csrf_token, ENV["ENCRYPTION_KEY"], std::stoi(ENV["ENCRYPTION_ROUNDS"]));

        redis.setex("csrf_token:" + encrypt_token(session_id, ENV["ENCRYPTION_KEY"], std::stoi(ENV["ENCRYPTION_ROUNDS"])), 3600, encrypted_csrf_token);
        redis.setex("token_uses:" + encrypt_token(session_id, ENV["ENCRYPTION_KEY"], std::stoi(ENV["ENCRYPTION_ROUNDS"])), 3600, std::to_string(max_uses));
        
        res.write(crow::json::wvalue({{"session_id", session_id}, {"csrf_token", csrf_token}, {"max_uses", max_uses}}).dump());
        res.add_header("Content-Type", "application/json");
        res.end();
    });

    // ──────────── Manga Pages ────────────
    // GET: /Mangas/<user>/<slug>/<chapter>/<page>
    CROW_ROUTE(app, "/Mangas/<string>/<string>/<int>/<int>")
    .methods("GET"_method)([](
        const crow::request& req, 
        crow::response& res, 
        std::string user, 
        std::string slug, 
        int chapter, 
        int page
    ) {
        if (!validateRequest(req, res)) return;
        
        std::string base_path = "Mangas/" + user + "/" + slug + "/" + 
                              std::to_string(chapter) + "/" + 
                              std::to_string(page);
        
        for (const auto& ext : VALID_EXTENSIONS) {
            std::string path = base_path + "." + ext;
            if (std::filesystem::exists(path)) {
                handleFileRead(res, path);
                return;
            }
        }
        
        processCodeHTTP(res, 404);
    });

    // POST: /Mangas/<user>/<slug>/<chapter>/<page>
    CROW_ROUTE(app, "/Mangas/<string>/<string>/<int>/<int>")
    .methods("POST"_method)([](
        const crow::request& req, 
        crow::response& res, 
        std::string user, 
        std::string slug, 
        int chapter, 
        int page
    ) {
        if (!validateRequest(req, res) || !validateCSRF(req, res)) return;
        
        std::string content_type = req.get_header_value("Content-Type");
        std::cout << "Content-Type recibido: " << content_type << std::endl;
        if (content_type.empty() || content_type.find("image/") == std::string::npos) {
            processCodeHTTP(res, 400);
            return;
        }
        
        std::string extension = content_type.substr(content_type.find("/") + 1);
        if (VALID_EXTENSIONS.find(extension) == VALID_EXTENSIONS.end()) {
            processCodeHTTP(res, 400);
            return;
        }
        
        std::string path = "Mangas/" + user + "/" + slug + "/" + 
                          std::to_string(chapter) + "/" + 
                          std::to_string(page) + "." + extension;
        
        handleFileWrite(res, req, path);
    });

    // ──────────── Media: User Profile ────────────
    // GET: /Media/Profiles/<user>/profilepicture.<ext>
    // GET: /Media/Profiles/<user>/bannerpicture.<ext>
    CROW_ROUTE(app, "/Media/Profiles/<string>/<string>")
    .methods("GET"_method)([](
        const crow::request& req,
        crow::response& res,
        std::string user,
        std::string filename
    ) {
        if (!validateRequest(req, res)) return;
    
        size_t dot_pos = filename.find_last_of('.');
        if (dot_pos == std::string::npos) {
            // No tiene extensión, buscamos archivo existente con extensiones válidas
            for (const auto& ext : VALID_EXTENSIONS) {
                std::string path = "Media/" + user + "/" + filename + "." + ext;
                if (std::filesystem::exists(path)) {
                    handleFileRead(res, path);
                    return;
                }
            }
            // No se encontró ninguno con extensiones válidas
            processCodeHTTP(res, 404);
            return;
        }
    
        // Si tiene extensión, validar y servir como antes
        std::string name = filename.substr(0, dot_pos);
        std::string ext = filename.substr(dot_pos + 1);
    
        if (name != "profilepicture" && name != "bannerpicture") {
            processCodeHTTP(res, 400);
            return;
        }
    
        if (VALID_EXTENSIONS.find(ext) == VALID_EXTENSIONS.end()) {
            processCodeHTTP(res, 400);
            return;
        }
    
        std::string path = "Media/" + user + "/" + filename;
        handleFileRead(res, path);
    });

    // POST: /Media/Profiles/<user>/profilepicture o bannerpicture
    CROW_ROUTE(app, "/Media/Profiles/<string>/<string>")
    .methods("POST"_method)([](
        const crow::request& req, 
        crow::response& res, 
        std::string user, 
        std::string type // "profilepicture" o "bannerpicture"
    ) {
        if (!validateRequest(req, res) || !validateCSRF(req, res)) return;
        
        if (type != "profilepicture" && type != "bannerpicture") {
            processCodeHTTP(res, 400);
            return;
        }
        
        std::string content_type = req.get_header_value("Content-Type");
        if (content_type.empty() || content_type.find("image/") == std::string::npos) {
            processCodeHTTP(res, 400);
            return;
        }
        
        std::string extension = content_type.substr(content_type.find("/") + 1);
        if (VALID_EXTENSIONS.find(extension) == VALID_EXTENSIONS.end()) {
            processCodeHTTP(res, 400);
            return;
        }
        
        std::string path = "Media/" + user + "/" + type + "." + extension;
        handleFileWrite(res, req, path);
    });

    // ──────────── Media: User Posts ────────────
    // GET: /Media/Profiles/<user>/Posts/<post_id>/<page>.<ext>
    CROW_ROUTE(app, "/Media/Profiles/<string>/Posts/<string>/<int>")
    .methods("GET"_method)([](
        const crow::request& req, 
        crow::response& res, 
        std::string user, 
        std::string post_id, 
        int page
    ) {
        if (!validateRequest(req, res)) return;
        
        std::string base_path = "Media/" + user + "/Posts/" + post_id + "/" + std::to_string(page);
        
        for (const auto& ext : VALID_EXTENSIONS) {
            std::string path = base_path + "." + ext;
            if (std::filesystem::exists(path)) {
                handleFileRead(res, path);
                return;
            }
        }
        
        processCodeHTTP(res, 404);
    });

    // POST: /Media/Profiles/<user>/Posts/<post_id>/<page>
    CROW_ROUTE(app, "/Media/Profiles/<string>/Posts/<string>/<int>")
    .methods("POST"_method)([](
        const crow::request& req, 
        crow::response& res, 
        std::string user, 
        std::string post_id, 
        int page
    ) {
        if (!validateRequest(req, res) || !validateCSRF(req, res)) return;
        
        std::string content_type = req.get_header_value("Content-Type");
        if (content_type.empty() || 
            (content_type.find("image/") == std::string::npos && content_type.find("video/") == std::string::npos)) {
            processCodeHTTP(res, 400);
            return;
        }
        
        std::string extension = content_type.substr(content_type.find("/") + 1);
        if (VALID_EXTENSIONS.find(extension) == VALID_EXTENSIONS.end()) {
            processCodeHTTP(res, 400);
            return;
        }
        
        std::string path = "Media/" + user + "/Posts/" + post_id + "/" + std::to_string(page) + "." + extension;
        handleFileWrite(res, req, path);
    }); 

    // ──────────── Media: Group Posts ────────────
    // GET: /Media/Profiles/<user>/Groups/<post_id>/<page>.<ext>
    CROW_ROUTE(app, "/Media/Profiles/<string>/Groups/<string>/<int>")
    .methods("GET"_method)([](
        const crow::request& req, 
        crow::response& res, 
        std::string user, 
        std::string post_id, 
        int page
    ) {
        if (!validateRequest(req, res)) return;
        
        std::string base_path = "Media/" + user + "/Groups/" + post_id + "/" + std::to_string(page);
        
        for (const auto& ext : VALID_EXTENSIONS) {
            std::string path = base_path + "." + ext;
            if (std::filesystem::exists(path)) {
                handleFileRead(res, path);
                return;
            }
        }
        
        processCodeHTTP(res, 404);
    });

    // POST: /Media/Profiles/<user>/Groups/<post_id>/<page>
    CROW_ROUTE(app, "/Media/Profiles/<string>/Groups/<string>/<int>")
    .methods("POST"_method)([](
        const crow::request& req, 
        crow::response& res, 
        std::string user, 
        std::string post_id, 
        int page
    ) {
        if (!validateRequest(req, res) || !validateCSRF(req, res)) return;
        
        std::string content_type = req.get_header_value("Content-Type");
        if (content_type.empty() || 
            (content_type.find("image/") == std::string::npos && content_type.find("video/") == std::string::npos)) {
            processCodeHTTP(res, 400);
            return;
        }
        
        std::string extension = content_type.substr(content_type.find("/") + 1);
        if (VALID_EXTENSIONS.find(extension) == VALID_EXTENSIONS.end()) {
            processCodeHTTP(res, 400);
            return;
        }
        
        std::string path = "Media/" + user + "/Groups/" + post_id + "/" + std::to_string(page) + "." + extension;
        handleFileWrite(res, req, path);
    }); 

    // ──────────── Media: Website Assets ────────────
    // GET: /Media/Website/<type>/<filename>
    CROW_ROUTE(app, "/Media/Website/<string>/<string>")
    .methods("GET"_method)([](
        const crow::request& req, 
        crow::response& res, 
        std::string asset_type, 
        std::string filename
    ) {
        if (!validateRequest(req, res)) return;
        
        // Validar tipos de assets permitidos
        if (asset_type != "CSS" && asset_type != "JS" && 
            asset_type != "Images" && asset_type != "Fonts") {
            processCodeHTTP(res, 400);
            return;
        }
        
        std::string path = "Media/Website/" + asset_type + "/" + filename;
        
        std::string content_type;
        if (asset_type == "CSS") content_type = "text/css";
        else if (asset_type == "JS") content_type = "application/javascript";
        else if (asset_type == "Fonts") {
            if (filename.find(".woff2") != std::string::npos) content_type = "font/woff2";
            else if (filename.find(".woff") != std::string::npos) content_type = "font/woff";
            else if (filename.find(".ttf") != std::string::npos) content_type = "font/ttf";
            else content_type = "application/octet-stream";
        }
        else { // Images
            std::string ext = filename.substr(filename.find_last_of(".") + 1);
            content_type = "image/" + (ext == "jpg" ? "jpeg" : ext);
        }
        
        if (std::filesystem::exists(path)) {
            std::ifstream file(path, std::ios::binary);
            if (!file) {
                processCodeHTTP(res, 500);
                return;
            }
            
            res.add_header("Content-Type", content_type);
            const size_t buffer_size = 8192;
            char buffer[buffer_size];
            
            while (file.read(buffer, buffer_size) || file.gcount() > 0) {
                res.write(std::string(buffer, file.gcount()));
            }
            
            file.close();
            res.end();
        } else {
            processCodeHTTP(res, 404);
        }
    });

    CROW_ROUTE(app, "/beep")
    .methods("GET"_method)([](const crow::request& req, crow::response& res) {
        res.write("boop");
        res.end();
    });
}