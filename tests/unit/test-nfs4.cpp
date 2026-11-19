#include <catch2/catch.hpp>

#include <cstdint>
#include <cstring>
#include <string>
#include <variant>
#include <vector>

#include "../../src/utils.h"
#include "../../src/virtualfiles/nfs/nfs4_ops.h"
#include "../../src/virtualfiles/nfs/rpc.h"
#include "nfs-test-utils.h"

using namespace pcapfs::nfs;
using namespace pcapfs::nfstest;

namespace {
    void putFixed(Buf &b, size_t n, uint8_t fill) { b.insert(b.end(), n, fill); }

    void putStateid(Buf &b, uint32_t seqid, uint8_t fill) {
        put32(b, seqid);
        putFixed(b, 12, fill);
    }

    void putBitmap(Buf &b, const std::vector<uint32_t> &words) {
        put32(b, static_cast<uint32_t>(words.size()));
        for (uint32_t w : words)
            put32(b, w);
    }

    // attribute values of a hand-built GETATTR reply
    Buf makeFattr() {
        Buf vals;
        put32(vals, 1);                       // 1  type = NF4REG
        put64(vals, 1234);                    // 4  size
        put32(vals, 90);                      // 10 lease_time (skipped)
        put64(vals, 777);                     // 20 fileid
        put32(vals, 0644);                    // 33 mode
        putOpaque(vals, "alice@example.org"); // 36 owner (17 bytes + padding)
        put64(vals, 1600000000);              // 53 time_modify
        put32(vals, 123456789);
        Buf f;
        putBitmap(f, {(1u << 1) | (1u << 4) | (1u << 10) | (1u << 20), (1u << 1) | (1u << 4) | (1u << 21)});
        put32(f, static_cast<uint32_t>(vals.size()));
        f.insert(f.end(), vals.begin(), vals.end());
        return f;
    }

    // strips the record mark, decodes the RPC header and returns the COMPOUND body decoder
    struct Message {
        Buf bytes;
        size_t bodyOffset = 0;
        XdrDecoder body() const {
            XdrDecoder d(bytes.data(), bytes.size());
            d.seek(bodyOffset);
            return d;
        }
    };

    Message fromCapture(const char *hex) {
        Message m;
        const Buf all = pcapfs::utils::hexStringToBytes(hex);
        m.bytes.assign(all.begin() + 4, all.end());
        const auto msg = decodeRpcMessage(m.bytes.data(), m.bytes.size());
        if (const auto *c = std::get_if<RpcCall>(&msg))
            m.bodyOffset = c->bodyOffset;
        else
            m.bodyOffset = std::get<RpcReply>(msg).bodyOffset;
        return m;
    }

    // payloads from the Wireshark sample capture nfsv4.1_pnfs.cap
    const char *const FRAME_7_EXCHANGE_ID_CALL =
        "800000f08ad3d4270000000000000002000186a300000004000000010000000100000020004708fe000000096e657461"
        "70702d323600000000000000000000000000000000000000000000000000000000000001000000010000002a5c8a9bfe"
        "0c095e92000000174c696e7578204e465376342e31206e65746170702d3236000000010100000000000000010000000a"
        "6b65726e656c2e6f72670000000000454c696e757820332e31302e302d3935372e656c372e7838365f36342023312053"
        "4d5020546875204f637420342032303a34383a3531205554432032303138207838365f36340000000000000000000000"
        "00000000";

    const char *const FRAME_8_EXCHANGE_ID_REPLY =
        "800000b88ad3d42700000001000000000000000000000000000000000000000000000000000000010000002a00000000"
        "e0148200000002d2000000010006010000000000983ba31ed7a911e800000010983ba31ed7a911e8bc0c000c29e91393"
        "00000010848b9312d7a911e8bc0c000c29e91393000000010000000c6e65746170702e636f6d0000000000244e657441"
        "70702052656c6561736520566f6f646f6f72616e6765725f5f392e362e300000260dcf5b0000000000000000";

    const char *const FRAME_56_OPEN_CALL =
        "800001289fd3d4270000000000000002000186a30000000400000001000000010000002400470901000000096e657461"
        "70702d3236000000000003e8000003e800000001000003e8000000000000000000000000000000010000000600000035"
        "000002d2e014820000000000000004020000001400000000000000000000000100000016000000200101000000000000"
        "0000000040000000cc9fd05b00f2fa80000000000000000000000012000000000000000200000000e0148200000002d2"
        "000000186f70656e2069643a0000002f000000000001480cae9b05080000000100000000000000020000001000000002"
        "0000000c0000000000000000000001b4000000000000000466696c650000000a000000030000002d0000000900000003"
        "0010011a0030a23a00000010";

    const char *const FRAME_57_OPEN_REPLY =
        "800001e09fd3d42700000001000000000000000000000000000000000000000000000000000000060000003500000000"
        "000002d2e0148200000000000000040200000014000000000000003f0000003f00000000000000160000000000000012"
        "0000000000000001008214e05b0088d9040000000000000116f82fd5dbb7fe3816f82fdf21a82a480000000400000003"
        "0000001000000002000000000000000200000001028214e05b0089d90400000000000000000000010000000000000000"
        "000000000000000000000001000000000000000a00000000000000200101000000000000000000008472000023a6c012"
        "00f2fa80000000000000000000000003000000000000002d0000000d0000000900000000000000030010011a0030a03a"
        "00000010000000bc0000000116f82fdf21a82a4800000000000000000000000000f2fa80000000000000000000000000"
        "00007284000001b4000000010000000f6d6f7261406e65746170702e636f6d000000000f6d6f7261406e65746170702e"
        "636f6d000000000000000000000000005be0bf7c21a82a48000000005be0bf7c21a82a48000000005be0bf7c21a82a48"
        "0000000100000001000000010000000f0000002000000000000000000000000000000000000000000000000000000000"
        "00000000";

    const char *const FRAME_62_WRITE_CALL =
        "800000e0a2d3d4270000000000000002000186a30000000400000001000000010000002400470901000000096e657461"
        "70702d3236000000000003e8000003e800000001000003e8000000000000000000000000000000010000000300000035"
        "000002d2e014820000000000000004020000001700000000000000000000000100000016000000300103000000000000"
        "000000008472000023a6c01200f2fa8000000000000000000101000000f2fa8000000000200000000000002600000000"
        "028214e05b0089d90400000000000000000000000000000200000005746573740a000000";

    const char *const FRAME_63_WRITE_REPLY =
        "80000070a2d3d42700000001000000000000000000000000000000000000000000000000000000030000003500000000"
        "000002d2e0148200000000000000040200000017000000000000003f0000003f00000000000000160000000000000026"
        "0000000000000005000000020000000000000000";

    const char *const FRAME_21_GETATTR_ROOT_REPLY =
        "800001308ed3d42700000001000000000000000000000000000000000000000000000000000000040000003500000000"
        "000002d2e0148200000000000000040200000003000000000000003f0000003f0000000000000018000000000000000a"
        "0000000000000020010100000000000000000000400000008baeea7ffff1fa8000000000000000000000000900000000"
        "000000030010011a00b0a03a00000000000000900000000216f42a14bb7ddfa8000000000000100000000000fff1fa80"
        "00000000000000000000000000000040000001ff000000050000000f726f6f74406e65746170702e636f6d000000000f"
        "726f6f74406e65746170702e636f6d000000000000001000000000005bd09d2434f45db0000000005bd0a8523b7ddfa8"
        "000000005bd0a8523b7ddfa80000000000000040";
}

TEST_CASE("NFS ops: names", "[nfs]") {
    CHECK(std::string(opName(op::PUTFH)) == "PUTFH");
    CHECK(std::string(opName(op::CLONE)) == "CLONE");
    CHECK(std::string(opName(op::REMOVEXATTR)) == "REMOVEXATTR");
    CHECK(std::string(opName(op::ILLEGAL)) == "ILLEGAL");
    CHECK(std::string(opName(76)) == "UNKNOWN");
    CHECK(std::string(cbOpName(op::CB_RECALL)) == "CB_RECALL");
    CHECK(std::string(nfsstat4Name(2)) == "NFS4ERR_NOENT");
    CHECK(std::string(nfsstat4Name(10096)) == "NFS4ERR_XATTR2BIG");
    for (uint32_t o = 3; o <= 75; ++o)
        CHECK(std::string(opName(o)) != "UNKNOWN");
}

TEST_CASE("NFS ops: tiny compound", "[nfs]") {
    Buf args;
    putOpaque(args, "");
    put32(args, 1);
    put32(args, 3);
    put32(args, op::PUTROOTFH);
    put32(args, op::LOOKUP);
    putOpaque(args, "a");
    put32(args, op::GETFH);
    XdrDecoder d(args.data(), args.size());
    const CompoundArgs c = decodeCompoundArgs(d);
    REQUIRE(c.complete);
    REQUIRE(c.ops.size() == 3);
    CHECK(c.ops[0].op == op::PUTROOTFH);
    CHECK(std::get<NameArgs>(c.ops[1].args).name == "a");
    CHECK(c.ops[2].op == op::GETFH);
    CHECK(d.remaining() == 0);

    Buf res;
    put32(res, 0);
    putOpaque(res, "");
    put32(res, 3);
    put32(res, op::PUTROOTFH); put32(res, 0);
    put32(res, op::LOOKUP); put32(res, 0);
    put32(res, op::GETFH); put32(res, 0);
    putOpaque(res, std::string("\x01\x02\x03\x04\x05", 5));
    XdrDecoder rd(res.data(), res.size());
    const CompoundRes r = decodeCompoundRes(rd);
    REQUIRE(r.complete);
    REQUIRE(r.ops.size() == 3);
    CHECK(r.ops[2].status == 0);
    CHECK(std::get<GetfhRes>(r.ops[2].res).fh == std::string("\x01\x02\x03\x04\x05", 5));
}

TEST_CASE("NFS ops: getattr reply packing", "[nfs]") {
    Buf res;
    put32(res, 0);
    putOpaque(res, "tag");
    put32(res, 1);
    put32(res, op::GETATTR);
    put32(res, 0);
    const Buf f = makeFattr();
    res.insert(res.end(), f.begin(), f.end());
    XdrDecoder d(res.data(), res.size());
    const CompoundRes r = decodeCompoundRes(d);
    REQUIRE(r.complete);
    const Fattr4 &a = std::get<GetattrRes>(r.ops.at(0).res).attrs;
    CHECK(*a.type == 1);
    CHECK(*a.size == 1234);
    CHECK(*a.fileid == 777);
    CHECK(*a.mode == 0644);
    CHECK(*a.owner == "alice@example.org");
    CHECK(a.timeModify->seconds == 1600000000);
    CHECK(a.timeModify->nseconds == 123456789);
    CHECK_FALSE(a.timeAccess.has_value());
}

TEST_CASE("NFS ops: fattr unknown attribute stops decoding", "[nfs]") {
    Buf vals;
    put64(vals, 42);                          // 4 size
    Buf f;
    putBitmap(f, {1u << 4, 0, 1u << (87 - 64)});
    put32(f, static_cast<uint32_t>(vals.size()));
    f.insert(f.end(), vals.begin(), vals.end());
    XdrDecoder d(f.data(), f.size());
    const Fattr4 a = decodeFattr4(d);
    CHECK(*a.size == 42);
}

TEST_CASE("NFS ops: fattr mode_umask, offline, time_deleg_* and open_arguments are skipped", "[nfs]") {
    Buf vals;
    put64(vals, 42);                          // 4 size
    put32(vals, 0755); put32(vals, 022);      // 81 mode_umask
    put32(vals, 1);                           // 83 offline
    put64(vals, 1600000000); put32(vals, 5);  // 84 time_deleg_access
    put64(vals, 1600000001); put32(vals, 6);  // 85 time_deleg_modify
    for (int i = 0; i < 5; ++i)               // 86 open_arguments: five bitmap4
        putBitmap(vals, {0x3u, static_cast<uint32_t>(i)});
    Buf f;
    putBitmap(f, {1u << 4, 0, (1u << (81 - 64)) | (1u << (83 - 64)) | (1u << (84 - 64)) | (1u << (85 - 64)) | (1u << (86 - 64))});
    put32(f, static_cast<uint32_t>(vals.size()));
    f.insert(f.end(), vals.begin(), vals.end());
    XdrDecoder d(f.data(), f.size());
    const Fattr4 a = decodeFattr4(d);
    CHECK(*a.size == 42);
    CHECK(d.remaining() == 0);

    // attribute 87 is not known: the walk stops there but 81..86 before it are consumed
    Buf f2;
    putBitmap(f2, {0, 0, (1u << (81 - 64)) | (1u << (87 - 64))});
    put32(f2, 8);
    put32(f2, 1); put32(f2, 2);
    XdrDecoder d2(f2.data(), f2.size());
    decodeFattr4(d2);
    CHECK(d2.remaining() == 0);
}

TEST_CASE("NFS ops: compound decoding is capped at MAX_COMPOUND_OPS operations", "[nfs]") {
    const uint32_t n = MAX_COMPOUND_OPS + 5;
    Buf args;
    putOpaque(args, ""); put32(args, 1); put32(args, n);
    for (uint32_t i = 0; i < n; ++i)
        put32(args, op::PUTROOTFH);
    XdrDecoder d(args.data(), args.size());
    const CompoundArgs c = decodeCompoundArgs(d);
    CHECK_FALSE(c.complete);
    CHECK(c.ops.size() == MAX_COMPOUND_OPS);

    // exactly the limit is still fine
    Buf ok;
    putOpaque(ok, ""); put32(ok, 1); put32(ok, MAX_COMPOUND_OPS);
    for (uint32_t i = 0; i < MAX_COMPOUND_OPS; ++i)
        put32(ok, op::PUTROOTFH);
    XdrDecoder od(ok.data(), ok.size());
    const CompoundArgs oc = decodeCompoundArgs(od);
    CHECK(oc.complete);
    CHECK(oc.ops.size() == MAX_COMPOUND_OPS);

    Buf res;
    put32(res, 0); putOpaque(res, ""); put32(res, n);
    for (uint32_t i = 0; i < n; ++i) { put32(res, op::PUTROOTFH); put32(res, 0); }
    XdrDecoder rd(res.data(), res.size());
    const CompoundRes r = decodeCompoundRes(rd);
    CHECK_FALSE(r.complete);
    CHECK(r.ops.size() == MAX_COMPOUND_OPS);

    Buf cb;
    putOpaque(cb, ""); put32(cb, 1); put32(cb, 0); put32(cb, n);
    for (uint32_t i = 0; i < n; ++i)
        put32(cb, op::CB_ILLEGAL);
    XdrDecoder cd(cb.data(), cb.size());
    const CbCompoundArgs cc = decodeCbCompoundArgs(cd);
    CHECK_FALSE(cc.complete);
    CHECK(cc.ops.size() == MAX_COMPOUND_OPS);

    Buf cbr;
    put32(cbr, 0); putOpaque(cbr, ""); put32(cbr, n);
    for (uint32_t i = 0; i < n; ++i) { put32(cbr, op::CB_ILLEGAL); put32(cbr, 0); }
    XdrDecoder crd(cbr.data(), cbr.size());
    const CbCompoundRes cr = decodeCbCompoundRes(crd);
    CHECK_FALSE(cr.complete);
    CHECK(cr.ops.size() == MAX_COMPOUND_OPS);
}

TEST_CASE("NFS ops: control file escapes wire strings", "[nfs]") {
    CHECK(escapeWireString("a\nb\"c\\d\x7f\x01") == "a\\x0ab\\\"c\\\\d\\x7f\\x01");
    CHECK(escapeWireString("plain") == "plain");
}

TEST_CASE("NFS ops: readdir reply", "[nfs]") {
    Buf res;
    put32(res, 0);
    putOpaque(res, "");
    put32(res, 1);
    put32(res, op::READDIR);
    put32(res, 0);
    putFixed(res, 8, 0xAA);                   // cookieverf
    for (int i = 0; i < 2; ++i) {
        put32(res, 1);                        // value follows
        put64(res, 100 + i);                  // cookie
        putOpaque(res, i == 0 ? "first" : "second.txt");
        putBitmap(res, {1u << 4});            // size
        put32(res, 8);
        put64(res, 10 * (i + 1));
    }
    put32(res, 0);                            // no more entries
    put32(res, 1);                            // eof
    XdrDecoder d(res.data(), res.size());
    const CompoundRes r = decodeCompoundRes(d);
    REQUIRE(r.complete);
    const auto &rd = std::get<ReaddirRes>(r.ops.at(0).res);
    REQUIRE(rd.entries.size() == 2);
    CHECK(rd.entries[0].name == "first");
    CHECK(*rd.entries[0].attrs.size == 10);
    CHECK(rd.entries[1].name == "second.txt");
    CHECK(*rd.entries[1].attrs.size == 20);
}

TEST_CASE("NFS ops: setattr error result still carries attrsset", "[nfs]") {
    Buf res;
    put32(res, 1);                            // compound status NFS4ERR_PERM
    putOpaque(res, "");
    put32(res, 2);
    put32(res, op::PUTFH); put32(res, 0);
    put32(res, op::SETATTR); put32(res, 1);   // NFS4ERR_PERM
    putBitmap(res, {0, 1u << 1});             // attrsset: mode (attr 33)
    XdrDecoder d(res.data(), res.size());
    const CompoundRes r = decodeCompoundRes(d);
    REQUIRE(r.complete);
    CHECK(r.status == 1);
    REQUIRE(r.ops.size() == 2);
    CHECK(r.ops[1].status == 1);
    CHECK(d.remaining() == 0);
}

TEST_CASE("NFS ops: layoutget result with one layout that has an empty body", "[nfs]") {
    Buf res;
    put32(res, 0);
    putOpaque(res, "");
    put32(res, 1);
    put32(res, op::LAYOUTGET); put32(res, 0);
    put32(res, 1);                                          // return_on_close
    put32(res, 7); put32(res, 0); put32(res, 0); put32(res, 0);   // stateid
    put32(res, 1);                                          // one layout4, 28 bytes: the minimum
    put32(res, 0); put32(res, 0);                           // offset
    put32(res, 0xffffffffu); put32(res, 0xffffffffu);       // length
    put32(res, 1);                                          // iomode LAYOUTIOMODE4_READ
    put32(res, 1);                                          // type LAYOUT4_NFSV4_1_FILES
    put32(res, 0);                                          // empty loc_body
    XdrDecoder d(res.data(), res.size());
    const CompoundRes r = decodeCompoundRes(d);
    REQUIRE(r.complete);
    REQUIRE(r.ops.size() == 1);
    CHECK(d.remaining() == 0);
}

TEST_CASE("NFS ops: other result unions", "[nfs]") {
    SECTION("LOCK denied") {
        Buf res;
        put32(res, 10010); putOpaque(res, ""); put32(res, 1);
        put32(res, op::LOCK); put32(res, 10010);
        put64(res, 5); put64(res, 6); put32(res, 2); put64(res, 99); putOpaque(res, "own");
        XdrDecoder d(res.data(), res.size());
        const CompoundRes r = decodeCompoundRes(d);
        REQUIRE(r.complete);
        CHECK(r.ops.at(0).status == 10010);
        CHECK(d.remaining() == 0);
    }
    SECTION("SETCLIENTID clid_inuse and plain error status") {
        Buf res;
        put32(res, 10017); putOpaque(res, ""); put32(res, 1);
        put32(res, op::SETCLIENTID); put32(res, 10017);
        putOpaque(res, "tcp"); putOpaque(res, "1.2.3.4.8.1");
        XdrDecoder d(res.data(), res.size());
        const CompoundRes r = decodeCompoundRes(d);
        REQUIRE(r.complete);
        CHECK(r.ops.at(0).status == 10017);
    }
    SECTION("READ_PLUS data and hole") {
        Buf res;
        put32(res, 0); putOpaque(res, ""); put32(res, 1);
        put32(res, op::READ_PLUS); put32(res, 0);
        put32(res, 1);                        // eof
        put32(res, 2);                        // two segments
        put32(res, 0); put64(res, 0); putOpaque(res, "abc");
        put32(res, 1); put64(res, 3); put64(res, 4096);
        XdrDecoder d(res.data(), res.size());
        const CompoundRes r = decodeCompoundRes(d);
        REQUIRE(r.complete);
        const auto &rp = std::get<ReadPlusRes>(r.ops.at(0).res);
        REQUIRE(rp.contents.size() == 2);
        CHECK(rp.contents[0].data.length == 3);
        CHECK(std::memcmp(res.data() + rp.contents[0].data.offset, "abc", 3) == 0);
        CHECK(rp.contents[1].length == 4096);
    }
    SECTION("COPY with NFS4ERR_OFFLOAD_NO_REQS") {
        Buf res;
        put32(res, 10094); putOpaque(res, ""); put32(res, 1);
        put32(res, op::COPY); put32(res, 10094);
        put32(res, 1); put32(res, 0);
        XdrDecoder d(res.data(), res.size());
        const CompoundRes r = decodeCompoundRes(d);
        REQUIRE(r.complete);
        CHECK(r.ops.at(0).status == 10094);
    }
}

TEST_CASE("NFS ops: unknown opcode gives partial compound", "[nfs]") {
    Buf args;
    putOpaque(args, "");
    put32(args, 0);
    put32(args, 3);
    put32(args, op::PUTROOTFH);
    put32(args, 9999);
    put32(args, op::GETFH);
    XdrDecoder d(args.data(), args.size());
    const CompoundArgs c = decodeCompoundArgs(d);
    CHECK_FALSE(c.complete);
    REQUIRE(c.ops.size() == 1);
    CHECK(c.ops[0].op == op::PUTROOTFH);

    Buf res;
    put32(res, 0); putOpaque(res, ""); put32(res, 2);
    put32(res, op::PUTROOTFH); put32(res, 0);
    put32(res, 9999); put32(res, 0);
    XdrDecoder rd(res.data(), res.size());
    const CompoundRes r = decodeCompoundRes(rd);
    CHECK_FALSE(r.complete);
    CHECK(r.ops.size() == 1);
}

TEST_CASE("NFS ops: truncated compound does not throw", "[nfs]") {
    Buf args;
    putOpaque(args, "");
    put32(args, 1);
    put32(args, 2);
    put32(args, op::PUTFH);
    put32(args, 8);                           // fh length beyond the data
    XdrDecoder d(args.data(), args.size());
    CompoundArgs c;
    REQUIRE_NOTHROW(c = decodeCompoundArgs(d));
    CHECK_FALSE(c.complete);
    Buf empty;
    XdrDecoder e(empty.data(), 0);
    CHECK_FALSE(decodeCompoundRes(e).complete);
}

TEST_CASE("NFS ops: callback compound", "[nfs]") {
    Buf args;
    putOpaque(args, "");
    put32(args, 1);                           // minorversion
    put32(args, 7);                           // callback_ident
    put32(args, 2);
    put32(args, op::CB_SEQUENCE);
    putFixed(args, 16, 0x11);
    put32(args, 4); put32(args, 0); put32(args, 0); put32(args, 0);
    put32(args, 0);                           // no referring call lists
    put32(args, op::CB_RECALL);
    putStateid(args, 1, 0x22);
    put32(args, 1);
    putOpaque(args, "FH12");
    XdrDecoder d(args.data(), args.size());
    const CbCompoundArgs c = decodeCbCompoundArgs(d);
    REQUIRE(c.complete);
    REQUIRE(c.ops.size() == 2);

    Buf res;
    put32(res, 0); putOpaque(res, ""); put32(res, 2);
    put32(res, op::CB_SEQUENCE); put32(res, 0);
    putFixed(res, 16, 0x11); put32(res, 4); put32(res, 0); put32(res, 0); put32(res, 0);
    put32(res, op::CB_RECALL); put32(res, 0);
    XdrDecoder rd(res.data(), res.size());
    const CbCompoundRes r = decodeCbCompoundRes(rd);
    CHECK(r.complete);
    CHECK(r.ops.size() == 2);
}


TEST_CASE("NFS ops: real capture, EXCHANGE_ID", "[nfs]") {
    const Message call = fromCapture(FRAME_7_EXCHANGE_ID_CALL);
    XdrDecoder d = call.body();
    const CompoundArgs c = decodeCompoundArgs(d);
    REQUIRE(c.complete);
    REQUIRE(c.ops.size() == 1);
    CHECK(d.remaining() == 0);

    const Message reply = fromCapture(FRAME_8_EXCHANGE_ID_REPLY);
    XdrDecoder rd = reply.body();
    const CompoundRes r = decodeCompoundRes(rd);
    REQUIRE(r.complete);
    REQUIRE(r.ops.size() == 1);
    CHECK(rd.remaining() == 0);
}

TEST_CASE("NFS ops: real capture, OPEN call and reply", "[nfs]") {
    const Message call = fromCapture(FRAME_56_OPEN_CALL);
    XdrDecoder d = call.body();
    const CompoundArgs c = decodeCompoundArgs(d);
    REQUIRE(c.complete);
    REQUIRE(c.ops.size() == 6);
    CHECK(c.ops[0].op == op::SEQUENCE);
    CHECK(std::get<PutfhArgs>(c.ops[1].args).fh.size() == 32);
    const auto &o = std::get<OpenArgs>(c.ops[2].args);
    CHECK(o.openType == 1);
    CHECK(o.claimType == 0);
    CHECK(o.file == "file");
    REQUIRE(o.createAttrs.has_value());
    CHECK(*o.createAttrs->size == 0);
    CHECK(*o.createAttrs->mode == 0664);
    CHECK(c.ops[3].op == op::GETFH);
    CHECK(d.remaining() == 0);

    const Message reply = fromCapture(FRAME_57_OPEN_REPLY);
    XdrDecoder rd = reply.body();
    const CompoundRes r = decodeCompoundRes(rd);
    REQUIRE(r.complete);
    REQUIRE(r.ops.size() == 6);
    CHECK(std::get<GetfhRes>(r.ops[3].res).fh.size() == 32);
    const Fattr4 &a = std::get<GetattrRes>(r.ops[5].res).attrs;
    CHECK(*a.type == 1);
    CHECK(*a.size == 0);
    CHECK(a.fsid->major == 15923840);
    CHECK(*a.fileid == 29316);
    CHECK(*a.mode == 0664);
    CHECK(*a.owner == "mora@netapp.com");
    CHECK(a.timeModify->seconds == 1541455740);
    CHECK(a.timeModify->nseconds == 564669000);
    CHECK(rd.remaining() == 0);
}

TEST_CASE("NFS ops: real capture, WRITE data span", "[nfs]") {
    const Message call = fromCapture(FRAME_62_WRITE_CALL);
    XdrDecoder d = call.body();
    const CompoundArgs c = decodeCompoundArgs(d);
    REQUIRE(c.complete);
    REQUIRE(c.ops.size() == 3);
    CHECK(c.ops[2].op == op::WRITE);
    const auto &w = std::get<WriteArgs>(c.ops[2].args);
    CHECK(w.offset == 0);
    REQUIRE(w.data.length == 5);
    CHECK(std::memcmp(call.bytes.data() + w.data.offset, "test\n", 5) == 0);
    CHECK(d.remaining() == 0);

    const Message reply = fromCapture(FRAME_63_WRITE_REPLY);
    XdrDecoder rd = reply.body();
    const CompoundRes r = decodeCompoundRes(rd);
    REQUIRE(r.complete);
    REQUIRE(r.ops.size() == 3);
    CHECK(std::get<WriteRes>(r.ops[2].res).count == 5);
}

TEST_CASE("NFS ops: real capture, GETATTR reply with many attributes", "[nfs]") {
    const Message reply = fromCapture(FRAME_21_GETATTR_ROOT_REPLY);
    XdrDecoder rd = reply.body();
    const CompoundRes r = decodeCompoundRes(rd);
    REQUIRE(r.complete);
    REQUIRE(r.ops.size() == 4);
    CHECK(std::get<GetfhRes>(r.ops[2].res).fh.size() == 32);
    const Fattr4 &a = std::get<GetattrRes>(r.ops[3].res).attrs;
    CHECK(*a.type == 2);
    CHECK(*a.size == 4096);
    CHECK(a.fsid->major == 4294048384ull);
    CHECK(a.fsid->minor == 0);
    CHECK(*a.fileid == 64);
    CHECK(*a.mode == 0777);
    CHECK(*a.owner == "root@netapp.com");
    CHECK(*a.ownerGroup == "root@netapp.com");
    CHECK(a.timeAccess->seconds == 1540398372);
    CHECK(a.timeAccess->nseconds == 888430000);
    CHECK(a.timeMetadata->seconds == 1540401234);
    CHECK(a.timeModify->seconds == 1540401234);
    CHECK(a.timeModify->nseconds == 998105000);
    CHECK(rd.remaining() == 0);
}


TEST_CASE("NFS ops: bitmap4 with more words than any attribute needs", "[nfs]") {
    SECTION("empty extra words are dropped") {
        Buf b;
        std::vector<uint32_t> words(20, 0);
        words[0] = 0x12; words[2] = 1;
        putBitmap(b, words);
        XdrDecoder dec(b.data(), b.size());
        const Bitmap4 bm = decodeBitmap4(dec);
        CHECK(dec.remaining() == 0);
        CHECK(bm.words.size() == 8);
        CHECK(bm.set() == (std::vector<unsigned>{1, 4, 64}));
    }
    SECTION("bits past the cap are an XDR error") {
        Buf b;
        std::vector<uint32_t> words(9, 0);
        words[8] = 1;
        putBitmap(b, words);
        XdrDecoder dec(b.data(), b.size());
        CHECK_THROWS_AS(decodeBitmap4(dec), XdrError);
    }
    SECTION("a bitmap of a million full words is rejected without materializing its bits") {
        Buf b;
        putBitmap(b, std::vector<uint32_t>(1000000, 0xFFFFFFFFu));
        XdrDecoder dec(b.data(), b.size());
        CHECK_THROWS_AS(decodeBitmap4(dec), XdrError);
    }
}
