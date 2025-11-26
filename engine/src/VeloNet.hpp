#pragma once
// VeloNet: minimal, high-throughput, encrypted image socket protocol.

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>
#include <array>
#include <optional>
#include <unordered_map>
#include <filesystem>
#include <chrono>
#include <mutex>

#include "EncryptionProc.hpp"   // AESGCM, deriveSessionKey
#include "KeyManagement.hpp"    // KeyGenerator
#include "FileManager.hpp"      // UUIDManagement

namespace VeloNet{

// ---------------------------------------------------------- PROTOCOL
// opcodes 
enum class OpCode : uint8_t{
    LIST        = 0x01,         // list UUIDs.
    FETCH       = 0x02,         // fetch by UUID.
    UPLOAD      = 0x03,         // upload an image.
    PING        = 0x04         // health/keepalive.
};

enum : uint8_t {
    FLAG_ENCRYPTED = 0x01,
    FLAG_COMPRESSED = 0x01
};

// fixed header, network byte order on the wire.
struct alignas(8) Header{
    uint8_t opcode;
    uint8_t flags;
    uint8_t token_len;
    uint8_t payload_len;

    static constexpr std::size_t SIZE = 8;

    // Encode/decode helpers.
    static void encode(const Header& h, std::array<unsigned char, SIZE>& out) noexcept;
    static Header decode(const unsigned char* in) noexcept;
};

// Status codes returned by server.
enum class Status : uint16_t {
    OK                  = 0,
    UNAUTHORIZED        = 1,
    BAD_REQUEST         = 2,
    NOT_FOUND           = 3,
    INTERNAL_ERROR      = 4
};

// Response frame header.
struct alignas(8) RespHeader{
    uint16_t status;        // status
    uint16_t flags;         // echo flags used
    uint32_t data_len;      // payload bytes

    static constexpr std::size_t SIZE = 8;
    static void encode(const RespHeader& h, std::array<unsigned char, SIZE>& out) noexcept;
    static RespHeader decode(const unsigned char* in) noexcept;
};

// ---------------------------------------------------------- CONFIG 

struct Config{
    std::string bind_addr = "0.0.0.0";
    uint16_t port = 8077;
    int backlog = 128;
    int threads = 4;    // worker threads
    std::filesystem::path image_root = "data/images";
    std::chrono::seconds token_ttl { 3600 }; // optional TTL for tokens 
    bool use_sendfile = true;   // if platform supports.
    bool encrypt_all = true;    // forces AES-GCM on payloads.
};

// ---------------------------------------------------------- In-memory index for images 

struct ImageMeta{
    std::filesystem::path path;
    std::uint64_t size = 0;
};

class ImageIndex{
public:
    explicit ImageIndex(std::filesystem::path root);

    // Build or refresh from disk.
    void rebuild();

    // Lookup by UUID (filename stem).
    std::optional<ImageMeta> find(std::string_view uuid) const;

    // Reutn all UUIDs
    std::vector<std::string> list() const;
private:
    std::filesystem::path root_;
    std::unordered_map<std::string,ImageMeta> map_; // uuid -> meta
};

// ---------------------------------------------------------- Auth/Session
struct SessionKey{
    std::array<unsigned char, 32> bytes{}; // AES-256 key
};

// Simple token-based auth with optional HKDF tie-in.
class AuthService{ // look to AuthService.cpp for the implementation.
public:
    AuthService();

    // Validate client token. Constant-time compare.
    bool validate(std::string_view token) const noexcept;

    // Derive a session key from master key + salt.
    sessionKey derive(const std::vector<unsigned char>& salt) const;

    // Replace master key at runtime.
    void reloadMasterKey();
private:
    // Helpers declared here.
    static bool isLikelyHex(std::string_view s) noexcept;
    static bool ct_equal(std::string_view a, std::string_view b) noexcept;
    void loadTokensUnlocked(); // read allow-listed tokens from disk.
private:
    // Storage
    mutable std::mutex mtx_;
    std::array<unsigned char, 32> master_key_{};
    std::vector<std::string> allowed_tokens_;
};

// ---------------------------------------------------------- Crypto wrapper per connection
/* CryptoContext is the per-connection encryption layer. It wraps AES-GCM from EncryptionProc 
 * and stores only what's needed at runtime: the active session key and the IV used for the last
 * encrypt operation.*/
class CryptoContext{
public:
    CryptoContext();

    // set a session key (32 bytes). Creates AESGCM instance.
    void setKey(const SessionKey& sk);

    // Encrypt/Decrypt whole buffers. AAD may be empty.
    // encrypt() returns ciphertext|| tag (16 bytes appended), matching AESGCM API contract.
    std::vector<unsigned char> encrypt(const std::vector<unsigned char>& plain,
                                        const std::vector<unsigned char>& aad);

    std::vector<unsigned char> decrypt(const std::vector<unsigned char>& cipher_with_tag,
                                        const std::vector<unsigned char>& aad);

    // Last IV used/generated for the last encrypt call.
    std::array<unsigned char,12> lastIV() const noexcept { return iv_; }

    // Generates a fresh IV.
    static std::array<unsigned char,12> genIV();
private:
    EncryptionProc::AESGCM aes_;
    std::array<unsigned char,12> iv_{};
    bool ready_ = false;
};

// // ---------------------------------------------------------- I/O primitives.
struct Message{
    Header header;
    std::string token;      // raw token bytes 
    std::vector<unsigned char> payload;
};

class Connection{
public:
    explicit Connection(int fd) noexcept : fd_(fd) {}
    ~Conection();

    int fd() const noexcept { return fd_; }

    // Read exactly n bytes unless EOF/error.
    bool readExact(unsigned char* buf, std::size_t n);
    bool writeExact(const unsigned char* buf, std::size_t n);

    // Frame helpers
    bool readHeader(Header& h);
    bool readToken(std::string& out, std::size_t n);
    bool readPayload(std::vector<unsigned char>& out, std::size_t n);

    bool writeResp(Satus st, uint16_t flags, const std::vector<unsigned char>& data);
private:
    int fd_ = -1;
};

// ---------------------------------------------------------- SERVICES
class ImageService{
public:
    explicit ImageService(ImageIndex& index) : index_(index) {}

    // LIST -> newline-separated UUIDs.
    std::vector<unsigned char> list();

    // FETCH -> raw bytes of the file.
    // Large sends may be streamed in the .cpp via sendfile; header only returns the whole
    // buffer path.
    std::optional<ImageMeta> locate(std::string_view uuid);
private:
    ImageIndex& index_;
};

class UploadService{
public:
    // Store new image bytes under UUID layout. Returns UUID.
    std::string store(const std::vector<unsigned char>& bytes,
                        std::string_view ext_hint = "img");
};

// ---------------------------------------------------------- DISPATCHER
class Dispatcher{
public:
    Dispatcher(AuthService& auth, ImageService& images) : 
        auth_(auth), images_(images) {}

    // Handle a request from one connection. Returns true if connection should persist.
    bool handle(Connection& conn, const Config& cfg);
private:
    bool handleList(Connection& conn, const Message& msg, const Config& cfg);
    bool handleFetch(Connection& conn, const Message& msg, const Config& cfg);
    bool handleUpload(Connection& conn, const Message& msg, const Config& cfg);
    bool handlePing(Connection& conn, const Message& msg, const Config& cfg);
private:
    AuthService& auth_;
    ImageService& images_;
};

// ---------------------------------------------------------- SERVER 
class Server{
public:
    explicit Server(Config cfg);

    // Start blocking run loop. Creates listener, workers, and serves forever until stop().
    void run();

    // Signal setup. Safe to call from another thread.
    void stop() noexcept;
private:
    // platform listener setup.
    int openListener();
    void acceptLoop(int listen_fd);
    void workerLoop();

private:
    Config cfg_;
    std::atomic<bool> stopping_{false};

    // File descriptors are managed in the .cpp to keep the header portable.
    int listen_fd_{-1};

    // Shared state
    ImageIndex index_;
    AuthService auth_;
};

} // namespace VeloNet
