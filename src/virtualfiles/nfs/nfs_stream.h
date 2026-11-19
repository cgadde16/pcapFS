#ifndef PCAPFS_NFS_STREAM_H
#define PCAPFS_NFS_STREAM_H

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "../../commontypes.h"
#include "../../file.h"
#include "nfs4_ops.h"
#include "rpc.h"

namespace pcapfs {
    namespace nfs {

        struct NfsMessage {
            size_t index = 0;
            RpcRecord record;                   // spans/offsets below are relative to record.bytes
            bool isCall = false;                // by msg_type, never by direction
            std::optional<RpcCall> call;
            std::optional<RpcReply> reply;
            bool isNfs4 = false;                // prog 100003 vers 4 (for replies: of the matched call)
            bool isCallback = false;            // prog in 0x40000000..0x5fffffff
            std::optional<CompoundArgs> args;
            std::optional<CompoundRes> res;
            std::optional<CbCompoundArgs> cbArgs;
            std::optional<CbCompoundRes> cbRes;
            std::optional<GssCred> gss;
            std::optional<size_t> matchedIndex; // call <-> reply pairing by xid
            bool retransmission = false;
            // offset in record.bytes of the (unwrapped) COMPOUND body that was decoded; 0 if none
            size_t compoundOffset = 0;
        };

        struct NfsStream {
            std::vector<NfsMessage> messages;
        };

        // record marks announcing a bigger fragment, or records growing beyond maxRecord, are treated as garbage
        struct NfsStreamLimits {
            uint32_t maxFragment = MAX_FRAGMENT_LEN;
            uint64_t maxRecord = 256ull << 20;
        };

        NfsStream parseNfsStream(const uint8_t *buffer, size_t len,
                                 const std::vector<std::pair<uint64_t, TimePoint>> &connectionBreaks,
                                 const NfsStreamLimits &limits = NfsStreamLimits());

        bool isNfsCandidate(const FilePtr &tcpFile, const Bytes &buffer, bool checkNonDefaultPorts);

        std::string renderControlText(const NfsStream &stream);

        struct NfsEndpoints {
            std::string serverIP;
            std::string clientIP;
            bool valid = false;
        };

        // RpcRecord::direction 0 is the sender of the first TCP chunk (the tcp file's srcIP), 1 the dstIP
        // callback-only streams (the server sends the calls) yield the server as the calling side
        NfsEndpoints deriveEndpoints(const NfsStream &stream, const FilePtr &tcpFile);

    }
}

#endif //PCAPFS_NFS_STREAM_H
