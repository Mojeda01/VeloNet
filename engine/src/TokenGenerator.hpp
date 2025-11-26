#pragma once
#include <string>

namespace webAPI{

class TokenGenerator{
public:
    // Generate a random token of specified byte length
    static std::string generateToken(size_t length = 32);

    // define the master directory for the token directory.
    const std::string masterTokenDirectory(const std::string& masterTokenPath);

};

}
