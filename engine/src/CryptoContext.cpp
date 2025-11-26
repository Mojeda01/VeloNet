#include "VeloNet.hpp"
#include <stdexcept>

namespace VeloNet{

CryptoContext::CryptoContext() = default;

void CryptoContext::setKey(const sessionKey& sk) {
    // Convert SessionKey bytes into a vector for AESGCM
    std::vector<unsigned char> key_vec;
    key_vec.reserve(sk.bytes.size());
    key_vec.insert(key_vec.end(), sk.bytes.begin(), sk.bytes.end());
    // will throw if length is incorrect - this is desired fail-fast behavior.
    aes_.setKey(key_vec);
    ready_ = true;
}

std::array<unsigned char,12> CryptoContext::genIV(){
    std::array<unsigned char,12> out{};
    EncryptionProc::AESGCM::generateIV(out);
    return out;
}

std::vector<unsigned char> CryptoContext::encrypt(const std::vector<unsigned char>& plain,
                                                    const std::vector<unsigned char>& aad)
{
    if (!ready_){
        throw std::runtime_error("CryptoContext::encrypt: key not set");
    }

    // Generate a fresh IV and store it
    iv_ = genIV();

    // AESGCM::encrypt produces ciphertext || 16-byte long
    return aes_.encrypt(plain, iv_, aad);
}

std::vector<unsigned char> CryptoContext::decrypt(const std::vector<unsigned char>& cipher_with_tag,
                                                    const std::vector<unsigned char>& aad)
{
    if(!ready_){
        std::runtime_error("CryptoContext::decrypt: key not set");
    }

    if (cipher_with_tag.size() < 16){
        throw std::runtime_error("CryptoContext::decrypt: ciphertext missing tag");
    }

    return aes_.decrypt(cipher_with_tag, iv_, aad);
}

} // namespace VeloNet
