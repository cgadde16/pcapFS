#include "xdr.h"

namespace pcapfs {
    namespace nfs {

        void XdrDecoder::need(size_t n) const {
            if (n > size - cursor)
                throw XdrError("XDR: truncated data (need " + std::to_string(n) + " bytes, have " +
                               std::to_string(size - cursor) + ")");
        }

        uint32_t XdrDecoder::u32() {
            need(4);
            const uint8_t *p = buf + cursor;
            cursor += 4;
            return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
                   (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
        }

        uint64_t XdrDecoder::u64() {
            need(8);
            const uint64_t hi = u32();
            const uint64_t lo = u32();
            return (hi << 32) | lo;
        }

        int64_t XdrDecoder::i64() {
            return static_cast<int64_t>(u64());
        }

        bool XdrDecoder::boolean() {
            const uint32_t v = u32();
            if (v > 1)
                throw XdrError("XDR: invalid boolean value " + std::to_string(v));
            return v == 1;
        }

        uint32_t XdrDecoder::readLength(uint32_t maxLen) {
            const uint32_t n = u32();
            if (n > maxLen)
                throw XdrError("XDR: declared length " + std::to_string(n) + " exceeds maximum " + std::to_string(maxLen));
            // check payload and padding against what is left, no overflow possible
            const size_t left = size - cursor;
            if (n > left || padding(n) > left - n)
                throw XdrError("XDR: declared length " + std::to_string(n) + " exceeds remaining data");
            return n;
        }

        std::string XdrDecoder::string(uint32_t maxLen) {
            const uint32_t n = readLength(maxLen);
            std::string result(reinterpret_cast<const char *>(buf + cursor), n);
            cursor += n + padding(n);
            return result;
        }

        std::string_view XdrDecoder::opaqueFixed(size_t n) {
            need(n);
            if (padding(n) > size - cursor - n)
                throw XdrError("XDR: truncated padding");
            std::string_view result(reinterpret_cast<const char *>(buf + cursor), n);
            cursor += n + padding(n);
            return result;
        }

        std::string_view XdrDecoder::opaqueVar(uint32_t maxLen) {
            const uint32_t n = readLength(maxLen);
            std::string_view result(reinterpret_cast<const char *>(buf + cursor), n);
            cursor += n + padding(n);
            return result;
        }

        XdrDecoder::Span XdrDecoder::opaqueVarSpan(uint32_t maxLen) {
            const uint32_t n = readLength(maxLen);
            Span result{cursor, n};
            cursor += n + padding(n);
            return result;
        }

        void XdrDecoder::skip(size_t n) {
            need(n);
            if (padding(n) > size - cursor - n)
                throw XdrError("XDR: truncated padding");
            cursor += n + padding(n);
        }

        uint32_t XdrDecoder::arrayCount(size_t minElem) {
            const uint32_t n = u32();
            if (static_cast<uint64_t>(n) * minElem > remaining())
                throw XdrError("XDR: array count " + std::to_string(n) + " exceeds remaining data");
            return n;
        }

        void XdrDecoder::seek(size_t newPos) {
            if (newPos > size)
                throw XdrError("XDR: seek beyond end of data");
            cursor = newPos;
        }

    }
}
