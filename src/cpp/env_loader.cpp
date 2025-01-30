#include <iostream>
#include <fstream>
#include <sstream>
#include <unordered_map>

#include "../env_loader.h"

std::unordered_map<std::string, std::string> load_env_file(const std::string& fileName) {
    std::unordered_map<std::string, std::string> variables;
    std::ifstream file(fileName);
    if (!file) {
        std::cerr << "Cannot open env file " << fileName << std::endl;
        return variables;
    }

    for (std::string line; std::getline(file, line);) {
        size_t pos = line.find('=');
        if (pos != std::string::npos)
            variables[line.substr(0, pos)] = line.substr(pos + 1);
    }

    return variables;
}