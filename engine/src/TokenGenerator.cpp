#include "TokenGenerator.hpp"
#include <filesystem>
#include <iostream>
#include <openssl/rand.h>
#include <sstream>
#include <iomanip>

namespace webAPI{

    std::string TokenGenerator::generateToken(size_t length) {
        std::vector<unsigned char> buffer(length);

        // Fill buffer with cryptographically secure random bytes
        if (RAND_bytes(buffer.data(), static_cast<int>(buffer.size())) != 1){
            throw std::runtime_error("Failed to generate random bytes for token");
        }

        // convert to hex string
        std::ostringstream oss;
        for (unsigned char byte : buffer){
            oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }
        return oss.str();
    }

    const std::string TokenGenerator::masterTokenDirectory(const std::string& masterTokenPath){
        std::filesystem::path dir = masterTokenPath;

        try {
            // check of the directory exists; create if not
            if (!std::filesystem::exists(dir)){
                std::filesystem::create_directories(dir);
                std::cout << ":: Created master token directory" << dir << std::endl;
            } else {
                std::cout << "Master token directory already exists: " << dir << std::endl;
            }

            // return absolute path 
            return std::filesystem::absolute(dir).string();
        }
        catch (const std::filesystem::filesystem_error& e){
            std::cerr << "--> Filesystem error: " << e.what() << std::endl;
            return "";
        }
    }

}
