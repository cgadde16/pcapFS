#ifndef PCAPFS_NFS_NFS4_ATTRS_H
#define PCAPFS_NFS_NFS4_ATTRS_H

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "xdr.h"

namespace pcapfs {
    namespace nfs {

        using Span = XdrDecoder::Span;

        struct Bitmap4 {
            std::vector<uint32_t> words;

            // bit N is stored in words[N / 32] with mask 1 << (N % 32) (RFC 8881 section 3.3.7)
            std::vector<unsigned> set() const;
        };

        struct Nfstime4 {
            int64_t seconds = 0;
            uint32_t nseconds = 0;
        };

        struct Fsid4 {
            uint64_t major = 0;
            uint64_t minor = 0;
        };

        struct ChangeInfo4 {
            uint64_t before = 0;
            uint64_t after = 0;
        };

        using Nfsfh4 = std::string; // raw bytes, at most 128
        using Verifier4 = std::array<uint8_t, 8>;
        using Sessionid4 = std::array<uint8_t, 16>;
        using Deviceid4 = std::array<uint8_t, 16>;

        Bitmap4 decodeBitmap4(XdrDecoder &dec);
        Nfstime4 decodeNfstime4(XdrDecoder &dec);
        Fsid4 decodeFsid4(XdrDecoder &dec);
        void decodeSpecdata4(XdrDecoder &dec);
        ChangeInfo4 decodeChangeInfo4(XdrDecoder &dec);
        void skipStateid4(XdrDecoder &dec);
        Nfsfh4 decodeNfsfh4(XdrDecoder &dec);
        Verifier4 decodeVerifier4(XdrDecoder &dec);
        Sessionid4 decodeSessionid4(XdrDecoder &dec);
        Deviceid4 decodeDeviceid4(XdrDecoder &dec);

        struct Fattr4 {
            std::optional<uint32_t> type;         // 1  nfs_ftype4
            std::optional<uint64_t> size;         // 4
            std::optional<Fsid4> fsid;            // 8
            std::optional<Nfsfh4> filehandle;     // 19
            std::optional<uint64_t> fileid;       // 20
            std::optional<uint32_t> mode;         // 33
            std::optional<std::string> owner;     // 36
            std::optional<std::string> ownerGroup; // 37
            std::optional<Nfstime4> timeAccess;   // 47
            std::optional<Nfstime4> timeCreate;   // 50
            std::optional<Nfstime4> timeMetadata; // 52
            std::optional<Nfstime4> timeModify;   // 53
        };

        // reads bitmap4 attrmask and opaque attr_vals<>; throws XdrError if the mask or the length is invalid,
        // undecodable attribute values just end the walk
        Fattr4 decodeFattr4(XdrDecoder &dec);

        // escapes a wire string for the control file: control bytes become \xNN, double quote and backslash get a backslash prefix
        std::string escapeWireString(std::string_view s);

    }
}

#endif //PCAPFS_NFS_NFS4_ATTRS_H
