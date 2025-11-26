#include "EncryptionProc.hpp"
#include "KeyManagement.hpp"

#include <openssl/kdf.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdexcept>
#include <vector>
#include <array>

namespace EncryptionProc{

AESGCM::AESGCM(const std::vector<unsigned char>& key) : key_(key) {
    if (key_.size() != 32){
        throw std::runtime_error("AESGCM requires a 256-bit key (32 bytes).");
    }
}

void AESGCM::setKey(const std::vector<unsigned char>& key){
    if (key.size() != 32){
        throw std::runtime_error("Invalid key length for AES-256-GCM.");
    }
    key_ = key;
}

std::array<unsigned char, 12> AESGCM::generateIV(){
    std::array<unsigned char. 12> iv{};
    if (RAND_bytes(iv.data(), static_cast<int>(iv.size())) != 1){
        throw std::runtime_error("IV Generation failed (RAND_bytes error)");
    }
    return iv
}

struct EncryptedData{
    std::vector<unsigned char> ciphertext;
    std::array<unsigned char, 16> tag;
    std::array<unsigned char, 12> iv;
};

EncryptedData AESGCM::encrypt(
    const std::vector<unsigned char>& plaintext,
    const std::array<unsigned char, 12>& iv,
    const std::vector<unsigned char>& aad
) const {
    using namespace KeyManagement;

    // Load master key if not already yet.
    std::vector<unsigned char> key = key_;
    if (key.empty()){
        key = KeyGenerator::loadKey("data/master.key");
        if (key.empty())
            throw std::runtime_error("Failed to load data/master.key");
    }
    if (key.size() != 32)
        throw std::runtime_error("Invalid AES-256 key length");

    // Prepare OpenSSL context 
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    EncryptedData result;
    result.iv = iv;
    result.ciphertext.resize(plaintext.size());

    int len = 0, total = 0;

    try{
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
            throw std::runtime_error("EVP_EncryptInit_ex failed");

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr) != 1)
            throw std::runtime_error("Failed to set IV length");

        if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1)
            throw std::runtime_error("Failed to initialize key and IV");

        if (!aad.empty() &&
             EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(), aad.size()), != 1)
            throw std::runtime_error("Failed to add AAD");

        if (EVP_EncryptUpdate(ctx, result.ciphertext.data(), &len,
                    plaintext.data(), plaintext.size()) != 1)
            throw std::runtime_error("Encryption failed");
        total = len;

        if (EVP_EncryptFinal_ex(ctx, result.ciphertext.data() + total, &len) != 1)
            throw std::runtime_error("EVP_EncryptFinal_ex failed");
        total += len;
        result.ciphertext.resize(total);

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                    result.tag.size(), result.tag.data()) != 1)
            throw std::runtime_error("Failed to get authentication tag");

        EVP_CIPHER_CTX_free(ctx);
        return result;
    }
    catch(...){
        EVP_CIPHER_CTX_free(ctx);
        throw;
    }
}

std::vector<unsigned char> AESGCM::decrypt(
    const std::vector<unsigned char>& ciphertext,
    const std::array<unsigned char, 12>& iv,
    const std::vector<unsigned char>& aad
) const {
    using namespace KeyManagement;

    // Load master key if not already in memory.
    std::vector<unsigned char> key = key_;
    if (key.empty()){
        key = KeyGenerator::loadKey("data/master.key");
        if (key.empty())
            throw std::runtime_error("Failed to load data/master.key");
    }
    if (key.size() != 32)
        throw std::runtime_error("Invalid AES-256 key length");

    // Ciphertext must contain tag appended at the end 
    if (ciphertext.size() < 16)
        throw std::runtime_error("Ciphertext too short (missing tag)");

    const size_t tagOffset = ciphertext.size() - 16;
    const unsigned char* tag = ciphertext.data() + tagOffset;
    const size_t cipherLen = tagOffset;

    std::vector<unsigned char> plaintext(cipherLen);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    int len = 0, total = 0;

    try{
        // initialize decryption
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
            throw std::runtime_error("EVP_DecryptInit_ex failed");

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr) != 1)
            throw std::runtime_error("Failed to set IV length");

        if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1)
            throw std::runtime_error("Failed to initialize key and IV");
        
        // Add optional AAD
        if (!aad.empty()){
            if (EVP_DecryptUpdate(ctx, nullptr, &len, aad.data(), aad.size()) != 1)
                throw std::runtime_error("Failed to add AAD");
        }

        // Decrypt ciphertext (excluding tag)
        if (EVP_DecryptUpdate(ctx, plaintext.data(), &len,
                    ciphertext.data(), cipherLen) != 1)
            throw std::runtime_error("Decryption failed");
        total = len;

        // Set authentication tag from end of ciphertext.
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag) != 1)
            throw std::runtime_error("Failed to set authentication tag");

        // Finalize and authenticate
        if (EVP_DecryptFinal_ex(ctx, plaintext.data() + total, &len) != 1)
            throw std::runtime_error("Tag verification failed (data tampered)");
        total += len;

        plaintext.resize(total);
        EVP_CIPHER_CTX_free(ctx);
        return plaintext;
    }
    catch(...){
        EVP_CIPHER_CTX_free(ctx);
        throw;
    }

}

std::vector<unsigned char> deriveSessionKey(
    const std::vector<unsigned char>& masterKey,
    const std::vector<unsigned char>& salt,
    std::size_t length
){

    if (length == 0){
        throw std::runtime_error("HKDF length must be > 0");
    }
    if (masterKey.empty()){
        throw std::runtime_error("HKDF masterKey is empty");
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!ctx) throw std::runtime_error("EVP_PKEY_CTX_new_id failed");

    std::vector<unsigned char> out(length);
    try{
        if (EVP_PKEY_derive_init(ctx) != 1)
            throw std::runtime_error("EVP_PKEY_derive_init failed");

        if (EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) != 1)
            throw std::runtime_error("EVP_PKEY_CTX_set_hkdf_md failed");

        // salt may be empty; openSSL permits nullptr with size 0.
        if (EVP_PKEY_CTX_set1_salt(ctx, salt.empty() ? nullptr : salt.data(),
                    static_cast<int>(salt.size())) != 1)
            throw std::runtime_error("EVP_PKEY_CTX_set1_hkdf_salt failed");

        if (EVP_PKEY_set1_hkdf_key(ctx, masterKey.data(), static_cast<int>(masterKey.size())) != 1)
            throw std::runtime_error("EVP_PKEY_CTX_set1_hkdf_key failed");

        size_t outlen = length;
        if (EVP_PKEY_derive(ctx, out.data(), &outlen) != 1 || outlen != length)
            throw std::runtime_error("EVP_PKEY_derive failed");

        EVP_PKEY_CTX_free(ctx);
        return out;
    } catch(...){
        EVP_PKEY_CTX_free(ctx);
        throw;
    }

}


}   // namespace EncryptionProc
