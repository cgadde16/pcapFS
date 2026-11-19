#ifndef PCAPFS_NFS_RPC_H
#define PCAPFS_NFS_RPC_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <variant>
#include <vector>

#include "../../commontypes.h"
#include "../../exceptions.h"
#include "xdr.h"

namespace pcapfs {
    namespace nfs {

        class RpcError : public PcapFsException {
        public:
            explicit RpcError(const std::string &what) : PcapFsException(what) {}
        };

        // record marking (RFC 5531 section 11)

        struct Piece {
            uint64_t bufferOffset;
            uint64_t length;
        };

        struct RpcRecord {
            uint8_t direction = 0;          // 0 = sender of the first TCP chunk, 1 = the other side
            TimePoint time;                 // of the chunk where the record starts
            uint64_t startOffset = 0;       // buffer offset of the first record mark byte
            std::vector<uint8_t> bytes;     // assembled payload without marks
            std::vector<Piece> pieces;      // buffer ranges of the payload, in order (marks excluded)
            bool complete = false;          // false if the buffer ended mid-record
            bool garbage = false;           // true: undecodable record mark

            // maps a byte range of the assembled payload onto buffer ranges (clipped to the payload)
            std::vector<Piece> piecesFor(size_t payloadOffset, size_t length) const;
        };

        // message headers (RFC 5531 section 9)

        constexpr uint32_t MSG_CALL = 0;
        constexpr uint32_t MSG_REPLY = 1;

        constexpr uint32_t AUTH_SYS = 1;
        constexpr uint32_t RPCSEC_GSS = 6;

        constexpr uint32_t MSG_ACCEPTED = 0;
        constexpr uint32_t MSG_DENIED = 1;

        constexpr uint32_t PROG_MISMATCH = 2;
        constexpr uint32_t RPC_MISMATCH = 0;
        constexpr uint32_t AUTH_ERROR = 1;

        constexpr uint32_t NFS_PROGRAM = 100003;
        constexpr uint32_t CALLBACK_PROG_MIN = 0x40000000;
        constexpr uint32_t CALLBACK_PROG_MAX = 0x5fffffff;

        constexpr uint32_t MAX_FRAGMENT_LEN = 64u << 20;

        inline bool isCallbackProg(uint32_t prog) { return prog >= CALLBACK_PROG_MIN && prog <= CALLBACK_PROG_MAX; }

        struct OpaqueAuth {
            uint32_t flavor = 0;
            XdrDecoder::Span body{0, 0}; // offset relative to the decoded message
        };

        struct GssCred {
            uint32_t gssProc = 0;
            uint32_t service = 0; // 1 none, 2 integrity, 3 privacy
        };

        struct RpcCall {
            uint32_t xid = 0;
            uint32_t prog = 0;
            uint32_t vers = 0;
            uint32_t proc = 0;
            OpaqueAuth cred;
            size_t bodyOffset = 0; // offset of the procedure arguments in the message
        };

        struct RpcReply {
            uint32_t xid = 0;
            uint32_t replyStat = 0;  // MSG_ACCEPTED / MSG_DENIED
            uint32_t acceptStat = 0; // only if accepted; 0 SUCCESS ... 5 SYSTEM_ERR
            uint32_t rejectStat = 0; // only if denied; 0 RPC_MISMATCH, 1 AUTH_ERROR
            size_t bodyOffset = 0;   // offset of the procedure results in the message
        };

        // decodes by msg_type, not by direction; throws XdrError / RpcError
        std::variant<RpcCall, RpcReply> decodeRpcMessage(const uint8_t *data, size_t len);

        GssCred decodeGssCred(const uint8_t *data, size_t len);

        const char *programName(uint32_t prog);
        const char *procedureName(uint32_t prog, uint32_t vers, uint32_t proc);
        const char *acceptStatName(uint32_t stat);
        const char *rejectStatName(uint32_t stat);

        // cheap port-independent detector on the first bytes of a TCP stream (with record mark)
        bool looksLikeRpc(const uint8_t *buffer, size_t len);

    }
}

#endif //PCAPFS_NFS_RPC_H
