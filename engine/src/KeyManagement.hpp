#pragma once
#include <string>
#include <vector>

namespace KeyManagement{

class KeyGenerator{
public:
    // generate a cryptographically secure random key of given length (default 32 bytes = 256 bits)
    static std::vector<unsigned char> generateKey(size_t length = 32);

    // save key bytes to a file (binary mode)
    static bool saveKey(const std::vector<unsigned char>& key, const std::string& path);

    // load key bytes from a file (binary mode)
    static std::vector<unsigned char> loadKey(const std::string& path);

    // convert key bytes to hexadecimal string for debugging/logging only.
    static std::string keyToHex(const std::vector<unsigned char>& key);
};

} // namespace keymanagement
