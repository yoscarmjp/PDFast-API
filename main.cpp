#include "crow.h"

int main() {
    crow::SimpleApp app;

    CROW_ROUTE(app, "/")([](){
        return "Hello, World!";
    });

    app.bindaddr("0.0.0.0").port(8003).multithreaded().run();
}