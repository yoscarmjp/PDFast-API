#include "crow.h"
#include "./src/controller.h"

int main() {
    crow::SimpleApp app;
    setup_routes(app);
    app.bindaddr("0.0.0.0").port(8003).multithreaded().run();
}