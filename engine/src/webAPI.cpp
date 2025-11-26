#include "webAPI.hpp"

#include <filesystem>
#include <vector>
#include <string>
#include <iostream>
#include <fstream>

namespace webAPI {

std::vector<std::filesystem::path> RequestData::listImages() const {
    std::vector<std::filesystem::path> imageFiles;
    std::filesystem::path baseDir = "data/images";

    // stop if directory doesn't exist
    if (!std::filesystem::exists(baseDir))
        return imageFiles;

    // search through all folders under data/images
    for (const auto& entry : std::filesystem::recursive_directory_iterator(baseDir)){
        // skip anything that's not a file
        if (!entry.is_regular_file())
            continue;

        // get file extension
        std::string extension = entry.path().extension().string();

        // add only common image types
        if (extension == ".png" || extension == ".jpg" || extension == ".jpeg")
            imageFiles.push_back(entry.path());
    }
    return imageFiles;
}

// Request validation: confirm requests come from the webapp (e.g., token or origin head check).
bool RequestData::validateRequest(const std::string& token, const std::string& validToken) const {

    // check token validity
    if (token.empty()){
        std::cerr << "Validation failed: empty token. \n";
        return false;
    }

    if (token == validToken){
        std::cout << "Request validated successfully.\n";
        return true;
    }
    std::cerr << "Validation failed: invalid token.\n";
    return false;

}

/* getImageData() locates an image file in the `data/images` directory using the given UUID,
 * reads its binary contents, and return those bytes as a `std::vector<unsigned char>`. It 
 * reconstructs the expected file path by taking the first two characters of the UUID to determine
 * the subdirectory, then searches for a file whose names matches that UUID (regardless of extension).
 * Once found, it opens the file in binary mode, loads all bytes into memory, and returns them.
 * If the UUID is invalid, the directory or file doesn't exist, or read operation fails, the 
 * function simply returns an empty vector.*/
std::vector<unsigned char> RequestData::getImageData(const std::string& uuid) const {
    std::vector<unsigned char> data;

    // Derive directory from UUID prefix.
    if (uuid.size() < 2){
        std::cerr << "Invalid UUID: too short. \n";
        return data;
    }

    std::string prefix = uuid.substr(0, 2);
    std::filesystem::path dir = std::filesystem::path("data/images") / prefix;

    if (!std::filesystem::exists(dir)){
        std::cerr << "Directory not found: " << dir << "\n";
        return data;
    }

    // Search for matching file (any extension)
    std::filesystem::path filePath;
    for (const auto& entry : std::filesystem::directory_iterator(dir)){
        if (entry.is_regular_file() && entry.path().stem().string() == uuid){
            filePath = entry.path();
            break;
        }
    }

    if (filePath.empty()){
        std::cerr << "File not found for UUID: " << uuid << "\n";
        return data;
    }

    // Read binary data
    std::ifstream file(filePath, std::ios::binary);
    if (!file){
        std::cerr << "Failed to open file: " << filePath << "\n";
        return data;
    }

    data.assign(std::istreambuf_iterator<char>(file), {});
    file.close();
    return data;
}

}   // namespace webapi.

