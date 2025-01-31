#ifndef CONTROLLER_H
#define CONTROLLER_H

#include "crow.h"

/**
 * @brief Setup the routes for the application
 * @param app The crow::SimpleApp instance
**/
void setup_routes(crow::SimpleApp& app);

#endif
