#include "AuthService.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>

#include "EncryptionProc.hpp"   // deriveSessionKey(...)
#include "KeyManagement.hpp"    // KeyGenerator::loadKey

namespace VeloNet{

// ---------------------------------------------------------- helpers 
bool AuthService::isLikelyHex(std::string_view s) noexcept{
    if (s.empty()) return false;
    for (unsigned char c : s){
        if (!std::isxdigit(c)) return false;
    }
    return true;
}

// Constant-time equality across possibly different lengths.
// Folds all bytes to avoid early-exit timing leakage.
bool AuthService::ct_equal(std::string_view a, std::string_view b) noexcept {
    size_t len = a.size();
    unsigned char diff = static_cast<unsigned char>(len ^ b.size());
    const size_t n = (len < b.size()) ? len : b.size();
    for (size_t i = 0; i < n; ++i) diff |= static_cast<unsigned char>(a[i] ^ b[i]);
    for (size_t i = n; i < a.size(); ++i) diff |= static_cast<unsigned char>(a[i]);
    for (size_t i = n; i < b.size(); ++i) diff |= static_cast<unsigned char>(b[i]);
    return diff == 0;
}

// ----------------------------------------------------------- Lifecycle
AuthService::AuthService() {
    reloadMasterKey();
    std::lock_guard<std::mutex> lk(mtx_);
    loadTokensUnlocked();
}

void AuthService::reloadMasterKey() {
    std::lock_guard<std::mutex> lk(mtx_);
    auto key = KeyManagement::KeyGenerator::loadKey(master_key_path_.string());
    if (key.size() != master_key_.size()){
        master_key_.fill(0);
        return;
    }
    std::copy(key.begin(), key.end(), master_key_.begin());
}

// Read allow-listed tokens from data/tokens/*.auth (filenames are the tokens).
void AuthService::loadTokensUnlocked(){
    allow_tokens_.clear();
    if (!std::filesystem::exists(token_dir_)) return;

    for (const auto& entry : std::filesystem::directory_iterator(token_dir_)){
        if (!entry.is_regular_file()) continue;
        const auto stem = entry.path().stem().string();
        if (!stem.empty() && isLikelyHex(stem)) {
            allowed_tokens_.push_back(stem);
        }
    }
}

// ---------------------------------------- API
bool AuthService::validate(std::string_view token) const noexcept {
    if (token.size() < 16 || token.size() > 128) return false;
    if (!isLikelyHex(token)) return false;

    // Constant-time aggregate scan over the allow-list.
    std::lock_guard<std::mutex> lk(mtx_);
    bool any_match = false;
    for (const auto& t : allowed_tokens_) {
        any_match |= ct_equal(token, std::string_view{t});
    }
    return any_match;
}

SessionKey AuthService::derive(const std::vector<unsigned char>& salt) const {
    std::array<unsigned char, 32> mk{};
    {
        std::lock_guard<std::mutex> lk(mtx_);
        mk = master_key_;
    }
    // Ensure master key is present 
    const bool unset = std::all_of(mk.begin(), mk.end(), [](unsigned char b){ return b == 0; });
    if (unset) {
        throw std::runtime_error("master.key not loaded.");
    }
    
    std::vector<unsigned char> mk_vec(mk.begin(), mk.end());
    auto out = EncryptionProc::deriveSessionKey(mk_vec, salt, 32);
    if (out.size() != 32){
        std::runtime_error("HKDF output length mismatch");
    }

    SessionKey sk;
    std::copy(out.begin(), out.end(), sk.bytes.begin());
    return sk;
}

} // namespace VeloNet
