#include "VeloNet.hpp"

#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <iostream>

namespace VeloNet{

Connection::~Connection(){
    if (fd_ >= 0){
        ::close(fd_);
        fd_ = -1;
    }
}

bool Connection::readExact(unsigned char* buf, std::size_t n){
    std::size_t offset = 0;

    while (offset < n){
        ssize_t rv = ::read(fd_, buf + offset, n - offset);
        if (rv == 0){
            // EOF 
            return false;
        }
        if (rv < 0){
            if (errno == EINTR){
                continue;
            }
            std::cerr << "read() failed on fd " << fd_ << ": " << std::strerror(errno) << "\n";
            return false;
        }
        offset += static_cast<std::size_t>(rv);
    }
    return true;
}

bool Connection::writeExact(const unsigned char* buf, std::size_t n){
    std::size_t offset = 0;
    while (offset < n){
        ssize_t rv = ::write(fd_, buf + offset, n - offset);
        if (rv <= 0){
            if (rv < 0 && errno == EINTR){
                continue;
            }
            std::cerr << "write() failed on fd " << fd_
                        << ": " << std::strerror(errno) << "\n";
            return false;
        }
        offset += static_cast<std::size_t>(rv);
    }
    return true;
}

bool Connection::readHeader(Header& h){
    std::array<unsigned char> Header::SIZE buf{};
    if (!readExact(buf.data, buf.size())){
        return false;
    }
    h = Header::decode(buf.data());
    return true;
}

bool Connection::readToken(std::string& out, std::size_t n){
    if (n == 0){
        out.clear();
        return true;
    }
    std::vector<unsigned char> buf(n);
    if (!readExact(buf.data(), buf.size())){
        return false;
    }
    out.assign(reinterpret_cast<const char*>(buf.data(), buf.size()));
    return true;
}

bool Connection::readPayload(std::vector<unsigned char>& out, std::size_t n){
    out.clear();
    if (n == 0){
        return true;
    }
    out.resize(n);
    return readExact(out.data(), out.size());
}

bool Connection::writeResp(Status st, uint16_t flags, const std::vector<unsigned char>& data){
    if (data.size() > std::numeric_limits<uint32_t>::max()){
        std::cerr << "writeResp: payload too large (" << data.size() << " bytes)\n";
        return false;
    }
    RespHeader rh;
    rh.status = static_cast<uint16_t>(st);
    rh.flags = flags;
    rh.data_len = static_cast<uint32_t>(data.size());

    std::array<unsigned char, RespHeader::SIZE> hdrBuf{};
    RespHeader::encode(rh, hdrBuf);

    if (!writeExact(hdrBuf.data(), hdrBuf.size())){
        return false;
    }
    
    if (!data.empty()){
        if (!writeExact(data.data(), data.size())){
            return false;
        }
    }

    return true;
}

};