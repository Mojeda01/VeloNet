#pragma once
#include <string>
#include <vector>
#include <filesystem>

namespace webAPI{

class RequestData{
public:

    // File discovery: walk `data/images/**` to collect `.png` (or other) files.
    std::vector<std::filesystem::path> listImages() const;

    // Declaring the webapp token to be the sent to the webAPI.
    std::string tokenFromWebApp;
    
    // Request validation: confirm requests come from the webapp (e.g., token or origin head check).
    bool validateRequest(const std::string& token, const std::string& validToken) const;

    // Serve data: read and return file bytes or metadata when validated.
    std::vector<unsigned char> getImageData(const std::string& uuid) const;

};

}
