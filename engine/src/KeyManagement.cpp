#include "KeyManagement.hpp"

#include <openssl/rand.h>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <iostream>

namespace KeyManagement{

std::vector<unsigned char> KeyGenerator::generateKey(size_t length){
    std::vector<unsigned char> key(length);
    if (RAND_bytes(key.data(), static_cast<int>(length)) != 1){
        throw std::runtime_error("Key generation failed (RAND_bytes error)");
    }
    return key;
}

bool KeyGenerator::saveKey(const std::vector<unsigned char>& key, const std::string& path){
    std::ofstream out(path, std::ios::binary);
    if (!out){
        std::cerr << "Error: cannot open file for writing: " << path << "\n";
        return false;
    }
    out.write(reinterpret_cast<const char*>(key.data()), key.size());
    out.close();
    return true;
}

std::vector<unsigned char> KeyGenerator::loadKey(const std::string& path){
    std::ifstream in(path, std::ios::binary);
    if (!in){
        std::cerr << "Error: cannot open key file: " << path << "\n";
        return {};
    }
    std::vector<unsigned char> key((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    in.close();
    return key;
}

std::string KeyGenerator::keyToHex(const std::vector<unsigned char>& key){
    std::ostringstream oss;
    for (unsigned char byte : key){
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    return oss.str();
}

} // namespace keymanagement
