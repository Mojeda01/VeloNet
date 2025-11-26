#include "VeloNet.hpp"
#include <fstream>

namespace VeloNet{

ImageIndex::ImageIndex(std::filesystem::path root) 
    : root_(std::move(root)){
        rebuild();
}

void ImageIndex::rebuild(){
    map_.clear();
    if (!std::filesystem::exists(root_) || !std::filesystem::is_directory(root_)) return;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(root_)){
        if (!entry.is_regular_file()){
            continue;
        }
        const auto& path = entry.path();
        const auto stem = path.stem().string();

        // skip files without valid stem
        if (stem.empty())
            continue;

        ImageMeta meta;
        meta.path = path;
        meta.size = static_cast<std::uint64_t>(std::filesystem::file_size(path));
        map_.emplace(stem, std::move(meta));
    }
}

std::optional<ImageMeta> ImageIndex::find(std::string_view uuid) const {
    auto it = map_.find(std::string(uuid));
    if (it == map_.end())
        return std::nullopt;
    return it->second;
}

std::vector<std::string> ImageIndex::list() const {
    std::vector<std::string> uuids;
    uuids.reserve(map_.size());
    for (const auto& [uuid, _] : map_)
        uuids.push_back(uuid);
    return uuids;
}

} // namespace VeloNet
