#pragma once 

/* Declarations for the cryptographic layer used by the HTTP listener.
 * Provides authenticated encryption (AES-256-GCM) and HKDF-based session
 * key derivation.
 * */

#include <vector>
#include <string>
#include <array>
#include <cstddef> // size_t

namespace EncryptionProc {

/* AES-256-GCM interface.
 * Encrypt/Decrypt buffers with per-message IV and optional AAD.
 * Throws std::runtime_error on errors.
 */

class AESGCM{
public:
    AESGCM() = default;
    explicit AESGCM(const std::vector<unsigned char>& key);     // expect 32 bytes.

    // Replace key at runtime. Expect 32 bytes.
    void setKey(const std::vector<unsigned char>& key);

    // Generate a 96-bit IV suitable for GCM.
    static std::array<unsigned char, 12> generateIV();

    // Encrypt plaintext with IV and optional AAD.
    // Returns ciphertext || 16-byte authentication tag appended.
    std::vector<unsigned char> encrypt(
        const std::vector<unsigned char>& plaintext,
        const std::array<unsigned char, 12>& iv,
        const std::vector<unsigned char>& aad = {}
    ) const;

    // Decrypt ciphertext containing trailing 16-byte tag.
    // Returns plaintext. Validates tag; throws on failure.
    std::vector<unsigned char> decrypt(
        const std::vector<unsigned char>& ciphertext,
        const std::array<unsigned char, 12>& iv,
        const std::vector<unsigned char>& aad = {}
    ) const;

private:
    std::vector<unsigned char> key_;    // 32 bytes.

};

/*
 * Derive an ephemeral session key using HKDF-SHA256.
 * masterKey: static or long-lived secret -- from KeyManagement.
 * salt: per-session random salt/nonce.
 * length: output key length in bytes (default 32).
 * Throws std::runtime_error on errors.
 * */
std::vector<unsigned char> deriveSessionKey(
    const std::vector<unsigned char>& masterKey,
    const std::vector<unsigned char>& salt,
    std::size_t length = 32
);

/*
 * Optional utility for debugging: render bytes as hex.
 * Do not call in production paths.
 * */
std::string toHex(const std::vector<unsigned char>& data);

} // namespace encryptionprotocol
