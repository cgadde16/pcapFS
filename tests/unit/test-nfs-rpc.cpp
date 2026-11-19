#include <catch2/catch.hpp>

#include <cstdint>
#include <string>
#include <variant>

#include "../../src/virtualfiles/nfs/rpc.h"
#include "../../src/utils.h"
#include "nfs-test-utils.h"

using namespace pcapfs::nfs;
using namespace pcapfs::nfstest;

namespace {
    constexpr uint32_t AUTH_NONE = 0;

    Buf buildCall(uint32_t xid, uint32_t prog, uint32_t vers, uint32_t proc, uint32_t credFlavor, const Buf &credBody) {
        Buf m;
        put32(m, xid); put32(m, 0); put32(m, 2); put32(m, prog); put32(m, vers); put32(m, proc);
        put32(m, credFlavor); put32(m, credBody.size());
        append(m, credBody);
        while (m.size() % 4) m.push_back(0);
        put32(m, 0); put32(m, 0);
        return m;
    }
}

TEST_CASE("NFS rpc: call and reply header decoding", "[nfs]") {
    Buf call = buildCall(0x1234, 100003, 4, 1, AUTH_NONE, {});
    append(call, Buf{0xde, 0xad, 0xbe, 0xef});
    auto msg = decodeRpcMessage(call.data(), call.size());
    REQUIRE(std::holds_alternative<RpcCall>(msg));
    const RpcCall &c = std::get<RpcCall>(msg);
    REQUIRE(c.xid == 0x1234);
    REQUIRE(c.prog == 100003);
    REQUIRE(c.vers == 4);
    REQUIRE(c.proc == 1);
    REQUIRE(c.cred.flavor == AUTH_NONE);
    REQUIRE(c.bodyOffset == call.size() - 4);

    SECTION("accepted reply") {
        Buf r;
        put32(r, 0x1234); put32(r, 1); put32(r, 0); put32(r, 0); put32(r, 0); put32(r, 0);
        auto m = decodeRpcMessage(r.data(), r.size());
        REQUIRE(std::holds_alternative<RpcReply>(m));
        const RpcReply &rep = std::get<RpcReply>(m);
        REQUIRE(rep.xid == 0x1234);
        REQUIRE(rep.replyStat == MSG_ACCEPTED);
        REQUIRE(rep.acceptStat == 0);
        REQUIRE(rep.bodyOffset == r.size());
    }
    SECTION("prog mismatch") {
        Buf r;
        put32(r, 1); put32(r, 1); put32(r, 0); put32(r, 0); put32(r, 0); put32(r, 2); put32(r, 3); put32(r, 4);
        const RpcReply rep = std::get<RpcReply>(decodeRpcMessage(r.data(), r.size()));
        REQUIRE(rep.acceptStat == 2);
    }
    SECTION("denied: auth error") {
        Buf r;
        put32(r, 1); put32(r, 1); put32(r, 1); put32(r, 1); put32(r, 5);
        const RpcReply rep = std::get<RpcReply>(decodeRpcMessage(r.data(), r.size()));
        REQUIRE(rep.replyStat == MSG_DENIED);
        REQUIRE(rep.rejectStat == 1);
    }
    SECTION("denied: rpc mismatch") {
        Buf r;
        put32(r, 1); put32(r, 1); put32(r, 1); put32(r, 0); put32(r, 2); put32(r, 2);
        const RpcReply rep = std::get<RpcReply>(decodeRpcMessage(r.data(), r.size()));
        REQUIRE(rep.rejectStat == 0);
    }
    SECTION("callback CALL is decoded by msg_type") {
        Buf cb = buildCall(7, 0x40000000, 1, 1, AUTH_NONE, {});
        REQUIRE(std::holds_alternative<RpcCall>(decodeRpcMessage(cb.data(), cb.size())));
    }
    SECTION("errors") {
        Buf bad = call;
        bad[11] = 3; // rpcvers 3
        REQUIRE_THROWS_AS(decodeRpcMessage(bad.data(), bad.size()), RpcError);
        Buf badType = call;
        badType[7] = 9;
        REQUIRE_THROWS_AS(decodeRpcMessage(badType.data(), badType.size()), pcapfs::PcapFsException);
        REQUIRE_THROWS_AS(decodeRpcMessage(call.data(), 10), XdrError);
        Buf bigAuth;
        put32(bigAuth, 1); put32(bigAuth, 0); put32(bigAuth, 2); put32(bigAuth, 100003); put32(bigAuth, 4);
        put32(bigAuth, 1); put32(bigAuth, 1); put32(bigAuth, 401); bigAuth.resize(bigAuth.size() + 404);
        REQUIRE_THROWS_AS(decodeRpcMessage(bigAuth.data(), bigAuth.size()), XdrError);
    }
}

TEST_CASE("NFS rpc: GSS credential body", "[nfs]") {
    Buf b;
    put32(b, 1); put32(b, 0); put32(b, 42); put32(b, 2);
    put32(b, 5); append(b, Buf{1, 2, 3, 4, 5, 0, 0, 0});
    GssCred g = decodeGssCred(b.data(), b.size());
    REQUIRE(g.gssProc == 0);
    REQUIRE(g.service == 2);

    Buf call = buildCall(1, 100003, 4, 1, RPCSEC_GSS, b);
    const RpcCall c = std::get<RpcCall>(decodeRpcMessage(call.data(), call.size()));
    REQUIRE(c.cred.flavor == RPCSEC_GSS);
    const GssCred inCall = decodeGssCred(call.data() + c.cred.body.offset, c.cred.body.length);
    REQUIRE(inCall.gssProc == 0);
    REQUIRE(inCall.service == 2);
}

TEST_CASE("NFS rpc: names", "[nfs]") {
    REQUIRE(std::string(programName(100003)) == "nfs");
    REQUIRE(std::string(programName(100000)) == "portmap");
    REQUIRE(std::string(programName(100005)) == "mount");
    REQUIRE(std::string(programName(100021)) == "nlm");
    REQUIRE(std::string(programName(100024)) == "status");
    REQUIRE(std::string(programName(100227)) == "nfs_acl");
    REQUIRE(std::string(programName(0x40000000)) == "nfs4_cb");
    REQUIRE(std::string(programName(0x5fffffff)) == "nfs4_cb");
    REQUIRE(std::string(programName(0x60000000)) == "unknown");
    REQUIRE(std::string(procedureName(100003, 4, 1)) == "COMPOUND");
    REQUIRE(std::string(procedureName(100003, 4, 0)) == "NULL");
    REQUIRE(std::string(procedureName(0x40000001, 1, 1)) == "CB_COMPOUND");
    REQUIRE(std::string(procedureName(0x40000001, 1, 0)) == "CB_NULL");
    REQUIRE(std::string(procedureName(100003, 3, 1)) == "unknown");
    REQUIRE(std::string(acceptStatName(5)) == "SYSTEM_ERR");
    REQUIRE(std::string(rejectStatName(1)) == "AUTH_ERROR");
}

TEST_CASE("NFS rpc: looksLikeRpc", "[nfs]") {
    Buf call = buildCall(1, 100003, 4, 1, AUTH_NONE, {});
    const Buf rec = withMark(call);
    REQUIRE(looksLikeRpc(rec.data(), rec.size()));
    Buf badProg = buildCall(1, 12345, 4, 1, AUTH_NONE, {});
    const Buf rec2 = withMark(badProg);
    REQUIRE(!looksLikeRpc(rec2.data(), rec2.size()));
    REQUIRE(!looksLikeRpc(rec.data(), 10));
    Buf shortMark = recordMark(8, true);
    append(shortMark, call);
    REQUIRE(!looksLikeRpc(shortMark.data(), shortMark.size()));
    const char http[] = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
    REQUIRE(!looksLikeRpc(reinterpret_cast<const uint8_t *>(http), sizeof(http)));
}

TEST_CASE("NFS rpc: COMPOUND call and reply from a real capture", "[nfs]") {
    const std::string callHex =
        "800000808cd3d4270000000000000002000186a300000004000000010000000100000020004708fe000000096e65746170702d3236"
        "000000000000000000000000000000000000000000000000000000000000010000000200000035000002d2e0148200000000000000"
        "0402000000010000000000000000000000000000003a00000000";
    const std::string replyHex =
        "800000588cd3d42700000001000000000000000000000000000000000000000000000000000000020000003500000000000002d2e0148200000000"
        "000000040200000001000000000000003f0000003f000000000000003a00000000";
    const pcapfs::Bytes callBytes = pcapfs::utils::hexStringToBytes(callHex);
    const pcapfs::Bytes replyBytes = pcapfs::utils::hexStringToBytes(replyHex);

    auto cm = decodeRpcMessage(callBytes.data() + 4, callBytes.size() - 4);
    auto rm = decodeRpcMessage(replyBytes.data() + 4, replyBytes.size() - 4);
    REQUIRE(std::holds_alternative<RpcCall>(cm));
    REQUIRE(std::holds_alternative<RpcReply>(rm));
    const RpcCall &c = std::get<RpcCall>(cm);
    const RpcReply &r = std::get<RpcReply>(rm);
    REQUIRE(c.xid == 0x8cd3d427);
    REQUIRE(c.prog == 100003);
    REQUIRE(c.vers == 4);
    REQUIRE(c.proc == 1);
    REQUIRE(c.cred.flavor == AUTH_SYS);
    REQUIRE(r.xid == c.xid);
    REQUIRE(r.replyStat == MSG_ACCEPTED);
    REQUIRE(r.acceptStat == 0);

    REQUIRE(looksLikeRpc(callBytes.data(), callBytes.size()));
}
