#include "nfs_stream.h"

#include <algorithm>
#include <unordered_map>

#include "../../properties.h"

namespace pcapfs {
    namespace nfs {

        namespace {
            // decodes the COMPOUND body starting at bodyOffset (offset of the procedure args/results). For a
            // GSS-protected message the body is skipped (privacy, control message) or unwrapped (integrity) first
            void decodeCompoundBody(NfsMessage &m, size_t bodyOffset, bool isCallMsg, bool isCbProg,
                                    const std::optional<GssCred> &gss) {
                const std::vector<uint8_t> &b = m.record.bytes;
                if (bodyOffset > b.size())
                    return;
                size_t start = bodyOffset;
                if (gss) {
                    if (gss->gssProc != 0)
                        return;
                    if (gss->service == 3)
                        return;
                    if (gss->service == 2) {
                        // rpc_gss_integ_data: u32 databody length, then seq_num, then the real payload
                        if (b.size() < bodyOffset + 8)
                            return;
                        start = bodyOffset + 8;
                    }
                }
                m.compoundOffset = start;
                XdrDecoder dec(b.data() + start, b.size() - start);
                if (isCallMsg) {
                    if (isCbProg)
                        m.cbArgs = decodeCbCompoundArgs(dec);
                    else
                        m.args = decodeCompoundArgs(dec);
                } else {
                    if (isCbProg)
                        m.cbRes = decodeCbCompoundRes(dec);
                    else
                        m.res = decodeCompoundRes(dec);
                }
            }

            void decodeCall(NfsMessage &m) {
                const RpcCall &c = *m.call;
                m.isCallback = isCallbackProg(c.prog);
                m.isNfs4 = c.prog == NFS_PROGRAM && c.vers == 4;
                const std::vector<uint8_t> &b = m.record.bytes;
                try {
                    if (c.cred.flavor == RPCSEC_GSS && c.cred.body.offset + c.cred.body.length <= b.size())
                        m.gss = decodeGssCred(b.data() + c.cred.body.offset, c.cred.body.length);
                } catch (const PcapFsException &) {
                    // undecodable credential: treated as not GSS-protected
                }
                if ((m.isNfs4 || m.isCallback) && c.proc == 1)
                    decodeCompoundBody(m, c.bodyOffset, true, m.isCallback, m.gss);
            }

            void decodeReplyBody(NfsMessage &m, const NfsMessage &call) {
                const RpcReply &r = *m.reply;
                m.isNfs4 = call.isNfs4;
                m.isCallback = call.isCallback;
                if (r.replyStat != MSG_ACCEPTED || r.acceptStat != 0)
                    return;
                if (call.call->proc != 1 || !(call.isNfs4 || call.isCallback))
                    return;
                decodeCompoundBody(m, r.bodyOffset, false, call.isCallback, call.gss);
            }
        }


        namespace {
            using Breaks = std::vector<std::pair<uint64_t, TimePoint>>;

            // splits one direction into RPC records (RFC 5531 record marking); after an undecodable record mark, e.g. a
            // zero-filled gap in the TCP stream, it resyncs at the next chunk that looks like an RPC record
            struct Splitter {
                NfsStreamLimits limits;
                static constexpr size_t MAX_FRAGS = 4096;

                uint8_t direction = 0;
                uint8_t mark[4] = {0, 0, 0, 0};
                size_t markHave = 0;
                bool inFragment = false;
                bool lastFragment = false;
                uint64_t fragRemaining = 0;
                bool recordStarted = false;
                bool searching = false;
                size_t fragCount = 0;
                RpcRecord cur;

                static bool plausibleStart(const uint8_t *buffer, size_t bufLen, uint64_t off) {
                    if (off + 12 > bufLen || !(buffer[off] & 0x80))
                        return false;
                    return looksLikeRpc(buffer + off, bufLen - off);
                }

                void feed(const uint8_t *buffer, size_t bufLen, uint64_t offset, uint64_t len, TimePoint time,
                          std::vector<RpcRecord> &out) {
                    if (searching) {
                        if (!plausibleStart(buffer, bufLen, offset))
                            return;
                        searching = false;
                    }
                    while (len > 0) {
                        if (!inFragment) {
                            if (!recordStarted) {
                                recordStarted = true;
                                cur = RpcRecord();
                                cur.direction = direction;
                                cur.time = time;
                                cur.startOffset = offset;
                                fragCount = 0;
                            }
                            mark[markHave++] = buffer[offset];
                            ++offset;
                            --len;
                            if (markHave < 4)
                                continue;
                            markHave = 0;
                            const uint32_t m = be32(mark);
                            const uint32_t fragLen = m & 0x7fffffffu;
                            lastFragment = (m & 0x80000000u) != 0;
                            const bool tooBig = cur.bytes.size() + fragLen > limits.maxRecord;
                            if (fragLen == 0 || fragLen > limits.maxFragment || ++fragCount > MAX_FRAGS || tooBig) {
                                if (tooBig) {
                                    cur.bytes.clear();
                                    cur.bytes.shrink_to_fit();
                                    cur.pieces.clear();
                                }
                                cur.garbage = true;
                                out.push_back(std::move(cur));
                                recordStarted = false;
                                searching = true;
                                return;
                            }
                            inFragment = true;
                            fragRemaining = fragLen;
                        } else {
                            const uint64_t n = std::min(len, fragRemaining);
                            cur.bytes.insert(cur.bytes.end(), buffer + offset, buffer + offset + n);
                            if (!cur.pieces.empty() &&
                                cur.pieces.back().bufferOffset + cur.pieces.back().length == offset)
                                cur.pieces.back().length += n;
                            else
                                cur.pieces.push_back({offset, n});
                            offset += n;
                            len -= n;
                            fragRemaining -= n;
                            if (fragRemaining == 0) {
                                inFragment = false;
                                if (lastFragment) {
                                    cur.complete = true;
                                    out.push_back(std::move(cur));
                                    recordStarted = false;
                                }
                            }
                        }
                    }
                }
            };

            std::vector<RpcRecord> splitWithResync(const uint8_t *buffer, size_t len, const Breaks &breaks,
                                                   const NfsStreamLimits &limits) {
                std::vector<RpcRecord> result;
                Splitter states[2];
                states[0].direction = 0;
                states[1].direction = 1;
                states[0].limits = states[1].limits = limits;
                for (size_t i = 0; i < breaks.size(); ++i) {
                    const uint64_t start = std::min<uint64_t>(breaks[i].first, len);
                    uint64_t end = (i + 1 < breaks.size()) ? breaks[i + 1].first : len;
                    end = std::min<uint64_t>(end, len);
                    if (end <= start)
                        continue;
                    states[i & 1].feed(buffer, len, start, end - start, breaks[i].second, result);
                }
                for (Splitter &s : states) {
                    if (s.recordStarted) {
                        result.push_back(std::move(s.cur));
                    }
                }
                std::stable_sort(result.begin(), result.end(), [](const RpcRecord &a, const RpcRecord &b) {
                    return a.startOffset < b.startOffset;
                });
                return result;
            }
        }

        NfsStream parseNfsStream(const uint8_t *buffer, size_t len,
                                 const std::vector<std::pair<uint64_t, TimePoint>> &connectionBreaks,
                                 const NfsStreamLimits &limits) {
            NfsStream stream;
            std::vector<RpcRecord> records = splitWithResync(buffer, len, connectionBreaks, limits);
            stream.messages.reserve(records.size());
            // (direction of the CALL, xid) -> index of the latest call: client and server (callback) calls on one
            // connection have independent xid spaces
            std::unordered_map<uint64_t, size_t> pending;
            const auto pendingKey = [](uint8_t callDirection, uint32_t xid) {
                return (static_cast<uint64_t>(callDirection) << 32) | xid;
            };

            for (RpcRecord &rec : records) {
                NfsMessage m;
                m.index = stream.messages.size();
                m.record = std::move(rec);
                if (m.record.garbage) {
                    stream.messages.push_back(std::move(m));
                    continue;
                }
                if (!m.record.complete) {
                    stream.messages.push_back(std::move(m));
                    continue;
                }
                try {
                    std::variant<RpcCall, RpcReply> v = decodeRpcMessage(m.record.bytes.data(), m.record.bytes.size());
                    if (std::holds_alternative<RpcCall>(v)) {
                        m.isCall = true;
                        m.call = std::get<RpcCall>(v);
                    } else {
                        m.reply = std::get<RpcReply>(v);
                    }
                } catch (const PcapFsException &) {
                    stream.messages.push_back(std::move(m));
                    continue;
                }

                if (m.isCall) {
                    decodeCall(m);
                    auto it = pending.find(pendingKey(m.record.direction, m.call->xid));
                    if (it != pending.end()) {
                        NfsMessage &prev = stream.messages[it->second];
                        if (!prev.matchedIndex) {
                            // retransmission: the reply stays paired with the original call
                            m.retransmission = true;
                            stream.messages.push_back(std::move(m));
                            continue;
                        }
                    }
                    pending[pendingKey(m.record.direction, m.call->xid)] = m.index;
                } else {
                    auto it = pending.find(pendingKey(m.record.direction ? 0 : 1, m.reply->xid));
                    if (it != pending.end()) {
                        NfsMessage &call = stream.messages[it->second];
                        m.matchedIndex = call.index;
                        if (call.matchedIndex)
                            m.retransmission = true;  // duplicate reply
                        else
                            call.matchedIndex = m.index;
                        decodeReplyBody(m, call);
                    }
                }
                stream.messages.push_back(std::move(m));
            }
            return stream;
        }

        bool isNfsCandidate(const FilePtr &tcpFile, const Bytes &buffer, bool checkNonDefaultPorts) {
            if (!tcpFile || tcpFile->getProperty(prop::protocol) != "tcp")
                return false;
            if (!looksLikeRpc(buffer.data(), buffer.size()))
                return false;
            if (tcpFile->getProperty(prop::srcPort) == "2049" || tcpFile->getProperty(prop::dstPort) == "2049")
                return true;
            if (tcpFile->meetsDecodeMapCriteria("nfs"))
                return true;
            if (!checkNonDefaultPorts)
                return false;
            const size_t fragLen = be32(buffer.data()) & 0x7fffffffu;
            const size_t avail = std::min(fragLen, buffer.size() - 4);
            try {
                const auto msg = decodeRpcMessage(buffer.data() + 4, avail);
                if (const RpcCall *c = std::get_if<RpcCall>(&msg))
                    return c->prog == NFS_PROGRAM || isCallbackProg(c->prog);
            } catch (const PcapFsException &) {
                // not an RPC message
            }
            return false;
        }

        namespace {
            // direction of the server's records; -1 if the stream has no messages
            int serverDirection(const NfsStream &stream) {
                // the client sends the normal calls, the server sends the callback calls
                int serverDir = -1;
                for (const NfsMessage &m : stream.messages) {
                    if (m.isCall) {
                        serverDir = m.isCallback ? m.record.direction : 1 - m.record.direction;
                        break;
                    }
                }
                if (serverDir < 0 && !stream.messages.empty())
                    serverDir = 1 - stream.messages.front().record.direction;  // no call seen: guess
                return serverDir;
            }
        }

        NfsEndpoints deriveEndpoints(const NfsStream &stream, const FilePtr &tcpFile) {
            NfsEndpoints ep;
            const int serverDir = serverDirection(stream);
            if (serverDir < 0 || !tcpFile)
                return ep;
            const bool serverIsSrc = (serverDir == 0);
            ep.serverIP = tcpFile->getProperty(serverIsSrc ? prop::srcIP : prop::dstIP);
            ep.clientIP = tcpFile->getProperty(serverIsSrc ? prop::dstIP : prop::srcIP);
            ep.valid = !ep.serverIP.empty();
            return ep;
        }

        namespace {
            std::string quotedName(const std::string &name) { return "\"" + escapeWireString(name) + "\""; }

            std::string argText(const ArgOp &a) {
                std::string s = opName(a.op);
                switch (a.op) {
                    case op::LOOKUP:
                    case op::REMOVE:
                    case op::LINK:
                        if (const auto *x = std::get_if<NameArgs>(&a.args))
                            s += " " + quotedName(x->name);
                        break;
                    case op::CREATE:
                        if (const auto *x = std::get_if<CreateArgs>(&a.args))
                            s += " " + quotedName(x->name);
                        break;
                    case op::RENAME:
                        if (const auto *x = std::get_if<RenameArgs>(&a.args))
                            s += " " + quotedName(x->oldname) + " -> " + quotedName(x->newname);
                        break;
                    case op::OPEN:
                        if (const auto *x = std::get_if<OpenArgs>(&a.args))
                            if (x->claimType == 0 || x->claimType == 2 || x->claimType == 3)
                                s += " " + quotedName(x->file);
                        break;
                    case op::READ:
                    case op::READ_PLUS:
                        if (const auto *x = std::get_if<ReadArgs>(&a.args))
                            s += " offset=" + std::to_string(x->offset) + " len=" + std::to_string(x->count);
                        break;
                    case op::WRITE:
                        if (const auto *x = std::get_if<WriteArgs>(&a.args))
                            s += " offset=" + std::to_string(x->offset) + " len=" + std::to_string(x->data.length);
                        break;
                    default:
                        break;
                }
                return s;
            }

            std::string argText(const CbArgOp &a) { return cbOpName(a.op); }

            template <typename Compound>
            std::string opsText(const Compound &c) {
                std::string out;
                for (const auto &o : c.ops) {
                    out += out.empty() ? " " : ", ";
                    out += argText(o);
                }
                if (!c.complete)
                    out += c.ops.empty() ? " ..." : ", ...";
                return out;
            }

            std::string procedureText(const NfsMessage &call) {
                const RpcCall &c = *call.call;
                const std::string proc = procedureName(c.prog, c.vers, c.proc);
                if (call.isNfs4 || call.isCallback)
                    return proc;
                return std::string(programName(c.prog)) + " " + proc;
            }

            std::string statusText(uint32_t status, const char *failedOp) {
                std::string s = nfsstat4Name(status);
                if (failedOp)
                    s += std::string(" (") + failedOp + ")";
                return s;
            }

            // empty if the reply is a success
            std::string replyError(const NfsMessage &m) {
                const RpcReply &r = *m.reply;
                if (r.replyStat != MSG_ACCEPTED)
                    return std::string("MSG_DENIED ") + rejectStatName(r.rejectStat);
                if (r.acceptStat != 0)
                    return acceptStatName(r.acceptStat);
                if (m.res && m.res->status != NFS4_OK)
                    return statusText(m.res->status, m.res->ops.empty() ? nullptr : opName(m.res->ops.back().op));
                if (m.cbRes && m.cbRes->status != NFS4_OK)
                    return statusText(m.cbRes->status, m.cbRes->ops.empty() ? nullptr : cbOpName(m.cbRes->ops.back().op));
                return "";
            }
        }

        std::string renderControlText(const NfsStream &stream) {
            std::string out;
            for (const NfsMessage &m : stream.messages) {
                if (m.record.garbage || !m.record.complete || (!m.call && !m.reply)) {
                    out += "[!] undecodable RPC record\n";
                } else if (m.isCall) {
                    out += "[>] " + procedureText(m);
                    if (m.args)
                        out += opsText(*m.args);
                    else if (m.cbArgs)
                        out += opsText(*m.cbArgs);
                    out += "\n";
                } else if (!m.matchedIndex) {
                    out += "[<] REPLY, Error: no matching call\n";
                } else {
                    out += "[<] " + procedureText(stream.messages[*m.matchedIndex]);
                    const std::string error = replyError(m);
                    if (!error.empty())
                        out += ", Error: " + error;
                    out += "\n";
                }
            }
            return out;
        }

    }
}
