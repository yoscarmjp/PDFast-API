#ifndef __CSRF_TOKEN_GENERATOR_H__
#define __CSRF_TOKEN_GENERATOR_H__

#include <string>
#include <sw/redis++/redis++.h>
#include "crow.h"

/**
 * A function that generates a CSRF token.
 * The token is a string with 32 characters, containing numbers and letters.
 * @return The generated token -> string
**/
std::string generate_csrf_token();

/**
 * A function that validates a CSRF token with the one stored in the Redis database.
 * @param req The request object -> crow::request
 * @return True if the token is valid, false otherwise -> bool
**/
bool validate_csrf_token(const crow::request& req);

/*
* The Redis database object
*/
extern sw::redis::Redis redis;

#endif