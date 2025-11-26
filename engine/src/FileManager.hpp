#pragma once 

#include <string>
#include <filesystem>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

namespace FileManagement{

class UUIDManagement{
public:

    // This function generates the UUIds themselves
    static boost::uuids::uuid generateUUID()
    {
        static thread_local boost::uuids::random_generator generator;
        return generator();
    }

    // converts the uuid to a string.
    static std::string uuidToString(const boost::uuids::uuid& id)
    {
        return boost::uuids::to_string(id);
    }

    
    // Builds the data/images directory
    static std::filesystem::path buildPath(const boost::uuids::uuid& id, 
                                           const std::string& extension = "img")
    {
        std::string idStr = boost::uuids::to_string(id);
        std::string prefix = idStr.substr(0,2);

        std::filesystem::path dir = "data/images/" + prefix;
        std::filesystem::create_directories(dir);

        return dir / (idStr + "." + extension);
    }

    // change the file names to the UUID.
    void renameFiles(const std::filesystem::path& sourceDir)
    {
        for (const auto& entry : std::filesystem::directory_iterator(sourceDir))
        {
            if (entry.is_regular_file())
            {
                auto id = generateUUID();
                // keep extension.
                auto newPath = buildPath(id, entry.path().extension().string().substr(1));
                std::filesystem::rename(entry.path(), newPath);
            }
        }
    }

    // This function processes the incoming files from the "upload" directory.
    void processIncomingFiles(const std::filesystem::path& uploadDir){
        for (const auto& entry : std::filesystem::directory_iterator(uploadDir)) {
            if (!entry.is_regular_file()) continue;

            auto id = generateUUID();
            std::string ext = entry.path().extension().string();

            // handle missing or short extensions
            if (!ext.empty() && ext.size() > 1){
                ext = ext.substr(1);
            } else {
                ext = "img";
            }

            auto newPath = buildPath(id, ext);

            if (std::filesystem::exists(newPath)){
                auto duplicateId = generateUUID();
                newPath = buildPath(duplicateId, ext);
            }
            std::filesystem::rename(entry.path(), newPath);
        }
    }

    // This functions ensures the entire process runs smoothly.
    // Think of this as the master function: it ensures directories exist, processes and 
    // uploads if valid.
    void manageFileFlow(){
        std::filesystem::path dataDir = "data/images";
        std::filesystem::path uploadDir = "uploads";

        // Ensure main directory exists
        if (!std::filesystem::exists(dataDir)){
            std::filesystem::create_directories(dataDir);
        }

        // If uploads folder does not exist or is empty, do nothing
        if (!std::filesystem::exists(uploadDir)) return;
        if (std::filesystem::is_empty(uploadDir)) return;

        // Process all uploaded files
        for (const auto& entry : std::filesystem::directory_iterator(uploadDir)){
            if (!entry.is_regular_file()) continue;

            auto id = generateUUID();
            std::string ext = entry.path().extension().string();
            if (!ext.empty() && ext.size() > 1){
                ext = ext.substr(1);
            }else{
                ext = "img";
            }
            auto newPath = buildPath(id, ext);

            // Check if file with same name already exists in uploads/
            if (std::filesystem::exists(newPath)){
                auto duplicateId = generateUUID();
                newPath = buildPath(duplicateId);
            }
            std::filesystem::rename(entry.path(), newPath);
        }
    }

};

}
