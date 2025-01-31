#include "crow.h"
#include "crow/middlewares/cors.h"
#include "./src/controller.h"

int main() {
    crow::App<crow::CORSHandler> app;
    auto& cors = app.get_middleware<crow::CORSHandler>();
    cors
        .global()
        .origin(ENV["CORS_ORIGIN"])
        .methods("POST"_method, "GET"_method, "OPTIONS"_method)
        .headers("Content-Type, Authorization, session_id, csrf_token");

    setup_routes(app);
    app.bindaddr("0.0.0.0").port(8003).multithreaded().run();
}