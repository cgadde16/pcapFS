#ifndef PCAPFS_NFS_XDR_H
#define PCAPFS_NFS_XDR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "../../exceptions.h"

namespace pcapfs {
    namespace nfs {

        inline uint32_t be32(const uint8_t *p) {
            return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
                   (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
        }

        class XdrError : public PcapFsException {
        public:
            explicit XdrError(const std::string &what) : PcapFsException(what) {}
        };

        // bounds-checked XDR (RFC 4506) decoder over a non-owning byte range
        class XdrDecoder {
        public:
            static constexpr uint32_t DEFAULT_MAX_LEN = 1u << 30;

            struct Span {
                size_t offset;   // offset of the payload within the decoded buffer
                uint32_t length; // payload length (without padding)
            };

            XdrDecoder(const uint8_t *data, size_t len) : buf(data), size(len) {}

            uint32_t u32();
            uint64_t u64();
            int64_t i64();
            bool boolean();

            std::string string(uint32_t maxLen = DEFAULT_MAX_LEN);
            std::string_view opaqueFixed(size_t n);
            std::string_view opaqueVar(uint32_t maxLen = DEFAULT_MAX_LEN);
            Span opaqueVarSpan(uint32_t maxLen = DEFAULT_MAX_LEN);

            // skips n bytes plus padding to a multiple of 4
            void skip(size_t n);

            // an array count can never exceed the remaining bytes divided by the minimal element size
            uint32_t arrayCount(size_t minElem = 4);

            size_t pos() const { return cursor; }
            size_t remaining() const { return size - cursor; }
            void seek(size_t newPos);
            const uint8_t *data() const { return buf; }

        private:
            void need(size_t n) const;
            static size_t padding(size_t n) { return (4 - (n & 3)) & 3; }
            // reads a length prefix, validates it (and its padding) and returns it
            uint32_t readLength(uint32_t maxLen);

            const uint8_t *buf;
            size_t size;
            size_t cursor = 0;
        };

    }
}

#endif //PCAPFS_NFS_XDR_H
