#include "rpc.h"

#include <algorithm>

namespace pcapfs {
    namespace nfs {

        namespace {
            constexpr uint32_t MAX_AUTH_BODY = 400;

            bool isKnownProgram(uint32_t prog) {
                switch (prog) {
                    case 100000: case NFS_PROGRAM: case 100005: case 100021: case 100024: case 100227:
                        return true;
                    default:
                        return isCallbackProg(prog);
                }
            }
        }

        std::vector<Piece> RpcRecord::piecesFor(size_t payloadOffset, size_t length) const {
            std::vector<Piece> result;
            uint64_t pos = 0; // payload offset of the current piece start
            const uint64_t end = static_cast<uint64_t>(payloadOffset) + length;
            for (const Piece &p : pieces) {
                const uint64_t pStart = pos;
                const uint64_t pEnd = pos + p.length;
                pos = pEnd;
                if (pEnd <= payloadOffset)
                    continue;
                if (pStart >= end)
                    break;
                const uint64_t from = std::max<uint64_t>(pStart, payloadOffset);
                const uint64_t to = std::min<uint64_t>(pEnd, end);
                result.push_back({p.bufferOffset + (from - pStart), to - from});
            }
            return result;
        }

        namespace {
            OpaqueAuth decodeOpaqueAuth(XdrDecoder &dec) {
                OpaqueAuth auth;
                auth.flavor = dec.u32();
                auth.body = dec.opaqueVarSpan(MAX_AUTH_BODY);
                return auth;
            }
        }

        std::variant<RpcCall, RpcReply> decodeRpcMessage(const uint8_t *data, size_t len) {
            XdrDecoder dec(data, len);
            const uint32_t xid = dec.u32();
            const uint32_t type = dec.u32();
            if (type == MSG_CALL) {
                RpcCall call;
                call.xid = xid;
                const uint32_t rpcVers = dec.u32();
                if (rpcVers != 2)
                    throw RpcError("RPC: unsupported rpcvers " + std::to_string(rpcVers));
                call.prog = dec.u32();
                call.vers = dec.u32();
                call.proc = dec.u32();
                call.cred = decodeOpaqueAuth(dec);
                decodeOpaqueAuth(dec);
                call.bodyOffset = dec.pos();
                return call;
            }
            if (type == MSG_REPLY) {
                RpcReply reply;
                reply.xid = xid;
                reply.replyStat = dec.u32();
                if (reply.replyStat == MSG_ACCEPTED) {
                    decodeOpaqueAuth(dec);
                    reply.acceptStat = dec.u32();
                    if (reply.acceptStat == PROG_MISMATCH) {
                        dec.u32();
                        dec.u32();
                    }
                } else if (reply.replyStat == MSG_DENIED) {
                    reply.rejectStat = dec.u32();
                    if (reply.rejectStat == RPC_MISMATCH) {
                        dec.u32();
                        dec.u32();
                    } else if (reply.rejectStat == AUTH_ERROR) {
                        dec.u32();
                    } else {
                        throw RpcError("RPC: invalid reject_stat " + std::to_string(reply.rejectStat));
                    }
                } else {
                    throw RpcError("RPC: invalid reply_stat " + std::to_string(reply.replyStat));
                }
                reply.bodyOffset = dec.pos();
                return reply;
            }
            throw RpcError("RPC: invalid msg_type " + std::to_string(type));
        }

        GssCred decodeGssCred(const uint8_t *data, size_t len) {
            XdrDecoder dec(data, len);
            GssCred cred;
            dec.u32();
            cred.gssProc = dec.u32();
            dec.u32();
            cred.service = dec.u32();
            dec.opaqueVar(MAX_AUTH_BODY);
            return cred;
        }

        const char *programName(uint32_t prog) {
            switch (prog) {
                case 100000: return "portmap";
                case NFS_PROGRAM: return "nfs";
                case 100005: return "mount";
                case 100021: return "nlm";
                case 100024: return "status";
                case 100227: return "nfs_acl";
                default:
                    if (isCallbackProg(prog))
                        return "nfs4_cb";
                    return "unknown";
            }
        }

        const char *procedureName(uint32_t prog, uint32_t vers, uint32_t proc) {
            if (prog == NFS_PROGRAM && vers == 4) {
                if (proc == 0)
                    return "NULL";
                if (proc == 1)
                    return "COMPOUND";
            } else if (isCallbackProg(prog)) {
                if (proc == 0)
                    return "CB_NULL";
                if (proc == 1)
                    return "CB_COMPOUND";
            }
            return "unknown";
        }

        const char *acceptStatName(uint32_t stat) {
            switch (stat) {
                case 0: return "SUCCESS";
                case 1: return "PROG_UNAVAIL";
                case 2: return "PROG_MISMATCH";
                case 3: return "PROC_UNAVAIL";
                case 4: return "GARBAGE_ARGS";
                case 5: return "SYSTEM_ERR";
                default: return "unknown";
            }
        }

        const char *rejectStatName(uint32_t stat) {
            switch (stat) {
                case 0: return "RPC_MISMATCH";
                case 1: return "AUTH_ERROR";
                default: return "unknown";
            }
        }

        bool looksLikeRpc(const uint8_t *buffer, size_t len) {
            if (len < 12)
                return false;
            const uint32_t fragLen = be32(buffer) & 0x7fffffffu;
            if (fragLen < 16 || fragLen > MAX_FRAGMENT_LEN)
                return false;
            const uint32_t type = be32(buffer + 8);
            if (type == 1)
                return true;
            if (type != 0 || len < 24)
                return false;
            return be32(buffer + 12) == 2 && isKnownProgram(be32(buffer + 16));
        }

    }
}
