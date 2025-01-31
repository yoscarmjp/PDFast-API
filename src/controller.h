#ifndef CONTROLLER_H
#define CONTROLLER_H

#include "crow.h"
#include "crow/middlewares/cors.h"

/**
 * @brief Setup the routes for the application
 * @param app The crow::SimpleApp instance
**/
void setup_routes(crow::App<crow::CORSHandler> app);

/**
 * Environment variables from .env
**/
extern std::unordered_map<std::string, std::string> ENV;

#endif
