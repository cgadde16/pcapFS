#include <catch2/catch.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include <boost/archive/text_iarchive.hpp>
#include <boost/archive/text_oarchive.hpp>

#include "../../src/virtualfiles/nfs/nfs_stream.h"
#include "../../src/virtualfiles/nfscontrol.h"
#include "nfs-test-utils.h"

using namespace pcapfs;
using namespace pcapfs::nfs;
using namespace pcapfs::nfstest;

namespace {
    size_t garbageRecords(const NfsStream &s) {
        return std::count_if(s.messages.begin(), s.messages.end(), [](const NfsMessage &m) { return m.record.garbage; });
    }

    size_t incompleteRecords(const NfsStream &s) {
        return std::count_if(s.messages.begin(), s.messages.end(),
                             [](const NfsMessage &m) { return !m.record.garbage && !m.record.complete; });
    }

    Buf compoundCall(uint32_t xid, uint32_t opnum) {
        Buf b;
        put32(b, xid); put32(b, 0); put32(b, 2); put32(b, 100003); put32(b, 4); put32(b, 1);
        put32(b, 0); put32(b, 0);   // cred AUTH_NONE
        put32(b, 0); put32(b, 0);   // verf
        put32(b, 0);                // tag ""
        put32(b, 0);                // minorversion
        put32(b, 1);                // 1 op
        put32(b, opnum);
        return withMark(b);
    }

    Buf compoundReply(uint32_t xid, uint32_t opnum) {
        Buf b;
        put32(b, xid); put32(b, 1); put32(b, 0);
        put32(b, 0); put32(b, 0);   // verf
        put32(b, 0);                // SUCCESS
        put32(b, 0);                // status NFS4_OK
        put32(b, 0);                // tag
        put32(b, 1);
        put32(b, opnum); put32(b, 0);
        return withMark(b);
    }

    NfsStream build() {
        const TimePoint t0{};
        const Buf c1 = compoundCall(0x11, 24);   // PUTROOTFH
        const Buf r1 = compoundReply(0x11, 24);
        const Buf c2 = compoundCall(0x22, 24);
        const Buf r2 = compoundReply(0x22, 24);
        const Buf rx = compoundReply(0x99, 24);

        Buf stream;
        std::vector<std::pair<uint64_t, TimePoint>> breaks;
        breaks.emplace_back(stream.size(), t0 + std::chrono::milliseconds(1)); append(stream, c1);
        breaks.emplace_back(stream.size(), t0 + std::chrono::milliseconds(2)); append(stream, r1);
        breaks.emplace_back(stream.size(), t0 + std::chrono::milliseconds(3)); append(stream, c2); append(stream, c2);
        breaks.emplace_back(stream.size(), t0 + std::chrono::milliseconds(4)); append(stream, r2); append(stream, rx);
        return parseNfsStream(stream.data(), stream.size(), breaks);
    }

   void stateid(Buf &b) {
        put32(b, 0);
        b.insert(b.end(), 12, 0);
    }

    Buf callWithOps(uint32_t xid, const std::vector<Buf> &ops) {
        Buf b;
        put32(b, xid); put32(b, 0); put32(b, 2); put32(b, 100003); put32(b, 4); put32(b, 1);
        put32(b, 0); put32(b, 0);
        put32(b, 0); put32(b, 0);
        put32(b, 0);
        put32(b, 0);
        put32(b, static_cast<uint32_t>(ops.size()));
        for (const Buf &o : ops)
            b.insert(b.end(), o.begin(), o.end());
        return withMark(b);
    }

    Buf replyWithOps(uint32_t xid, uint32_t status, const std::vector<std::pair<uint32_t, uint32_t>> &ops) {
        Buf b;
        put32(b, xid); put32(b, 1); put32(b, 0);
        put32(b, 0); put32(b, 0);
        put32(b, 0);
        put32(b, status);
        put32(b, 0);
        put32(b, static_cast<uint32_t>(ops.size()));
        for (const auto &o : ops) {
            put32(b, o.first);
            put32(b, o.second);
        }
        return withMark(b);
    }

    Buf deniedReply(uint32_t xid) {
        Buf b;
        put32(b, xid); put32(b, 1); put32(b, 1);
        put32(b, 1);   // AUTH_ERROR
        put32(b, 1);   // auth_stat
        return withMark(b);
    }

    Buf nameOp(uint32_t opnum, const std::string &name) {
        Buf b;
        put32(b, opnum);
        putOpaque(b, name);
        return b;
    }

    // chunk i is sent by direction i % 2: even chunks are calls, odd chunks replies
    NfsStream parseChunks(const std::vector<Buf> &chunks) {
        Buf stream;
        std::vector<std::pair<uint64_t, TimePoint>> breaks;
        int ms = 0;
        for (const Buf &c : chunks) {
            breaks.emplace_back(stream.size(), TimePoint{} + std::chrono::milliseconds(++ms));
            append(stream, c);
        }
        return parseNfsStream(stream.data(), stream.size(), breaks);
    }
}

TEST_CASE("NFS stream: pairs calls and replies", "[nfs]") {
    const NfsStream s = build();
    REQUIRE(s.messages.size() == 6);
    CHECK(garbageRecords(s) == 0);
    CHECK(incompleteRecords(s) == 0);

    CHECK(s.messages[0].isCall);
    CHECK(s.messages[0].record.direction == 0);
    CHECK(s.messages[0].isNfs4);
    REQUIRE(s.messages[0].args);
    CHECK(s.messages[0].args->ops.size() == 1);
    CHECK(s.messages[0].matchedIndex == 1);

    CHECK_FALSE(s.messages[1].isCall);
    CHECK(s.messages[1].record.direction == 1);
    CHECK(s.messages[1].matchedIndex == 0);
    REQUIRE(s.messages[1].res);
    CHECK(s.messages[1].res->status == 0);

    // retransmitted call: the reply is paired with the original, the later copy is only marked
    CHECK_FALSE(s.messages[2].retransmission);
    CHECK(s.messages[3].retransmission);
    CHECK(s.messages[2].matchedIndex == 4);
    CHECK_FALSE(s.messages[3].matchedIndex);
    CHECK(s.messages[4].matchedIndex == 2);

    // unmatched reply
    CHECK_FALSE(s.messages[5].matchedIndex);
    CHECK_FALSE(s.messages[5].res);
}

TEST_CASE("NFS stream: control text rendering", "[nfs]") {
    const std::string text = renderControlText(build());
    CHECK(text ==
          "[>] COMPOUND PUTROOTFH\n"
          "[<] COMPOUND\n"
          "[>] COMPOUND PUTROOTFH\n"
          "[>] COMPOUND PUTROOTFH\n"
          "[<] COMPOUND\n"
          "[<] REPLY, Error: no matching call\n");
}

TEST_CASE("NFS stream: control text shows the arguments of selected operations", "[nfs]") {
    Buf open;
    put32(open, op::OPEN); put32(open, 1); put32(open, 2); put32(open, 0);
    put64(open, 7); putOpaque(open, "owner");
    put32(open, 0);                                   // OPEN4_NOCREATE
    put32(open, 0); putOpaque(open, "new\nfile\"");   // CLAIM_NULL
    Buf openPrev;
    put32(openPrev, op::OPEN); put32(openPrev, 1); put32(openPrev, 1); put32(openPrev, 0);
    put64(openPrev, 7); putOpaque(openPrev, "owner");
    put32(openPrev, 0);
    put32(openPrev, 4);   // CLAIM_FH
    Buf rename;
    put32(rename, op::RENAME); putOpaque(rename, "old"); putOpaque(rename, "new");
    Buf read;
    put32(read, op::READ); stateid(read); put64(read, 4096); put32(read, 512);
    Buf write;
    put32(write, op::WRITE); stateid(write); put64(write, 8); put32(write, 2); putOpaque(write, "hello");
    Buf getfh;
    put32(getfh, op::GETFH);

    const NfsStream s = parseChunks({
        callWithOps(1, {nameOp(op::LOOKUP, "a\"b"), open, openPrev, rename, read, write, getfh}),
        replyWithOps(1, 0, {})});
    CHECK(renderControlText(s) ==
          "[>] COMPOUND LOOKUP \"a\\\"b\", OPEN \"new\\x0afile\\\"\", OPEN, RENAME \"old\" -> \"new\", "
          "READ offset=4096 len=512, WRITE offset=8 len=5, GETFH\n"
          "[<] COMPOUND\n");
}

TEST_CASE("NFS stream: control text marks a partially decoded call", "[nfs]") {
    Buf lookup = nameOp(op::LOOKUP, "x");
    Buf bad;
    put32(bad, 0xfffff);   // unknown opcode
    const NfsStream s = parseChunks({callWithOps(1, {lookup, bad})});
    CHECK(renderControlText(s) == "[>] COMPOUND LOOKUP \"x\", ...\n");
}

TEST_CASE("NFS stream: control text shows errors of replies", "[nfs]") {
    Buf putfh;
    put32(putfh, op::PUTFH); putOpaque(putfh, "fh");
    Buf bareLookup = nameOp(op::LOOKUP, "missing");
    const NfsStream s = parseChunks({
        callWithOps(1, {putfh, bareLookup}),
        replyWithOps(1, 2, {{op::PUTFH, 0}, {op::LOOKUP, 2}}),
        callWithOps(2, {putfh}),
        deniedReply(2),
        callWithOps(3, {putfh}),
        replyWithOps(3, 0, {{op::PUTFH, 0}}),
        callWithOps(4, {putfh}),
        replyWithOps(4, 1, {})});
    CHECK(renderControlText(s) ==
          "[>] COMPOUND PUTFH, LOOKUP \"missing\"\n"
          "[<] COMPOUND, Error: NFS4ERR_NOENT (LOOKUP)\n"
          "[>] COMPOUND PUTFH\n"
          "[<] COMPOUND, Error: MSG_DENIED AUTH_ERROR\n"
          "[>] COMPOUND PUTFH\n"
          "[<] COMPOUND\n"
          "[>] COMPOUND PUTFH\n"
          "[<] COMPOUND, Error: NFS4ERR_PERM\n");
}

TEST_CASE("NFS stream: control text for a reply without call and an undecodable record", "[nfs]") {
    Buf junk;
    put32(junk, 0x12345678);
    const NfsStream s = parseChunks({replyWithOps(9, 0, {}), withMark(junk)});
    CHECK(renderControlText(s) ==
          "[<] REPLY, Error: no matching call\n"
          "[!] undecodable RPC record\n");
}

TEST_CASE("NFS stream: control file serialization round trip keeps the TCP breaks", "[nfs]") {
    const auto tp = [](int64_t s) { return TimePoint(std::chrono::seconds(s)); };

    NfsControlFile f;
    f.setFilename("NFS.control");
    f.setFiletype("nfscontrol");
    f.setOffsetType("tcp");
    f.setIdInIndex(5);
    f.setFilesizeRaw(123);
    f.setFilesizeProcessed(123);
    f.setTimestamp(tp(10));
    Fragment fragment;
    fragment.id = 2;
    fragment.start = 0;
    fragment.length = 4096;
    f.fragments.push_back(fragment);
    f.tcpBreaks = {{0, tp(10)}, {200, tp(11)}, {4000, tp(12)}};

    std::stringstream ss;
    {
        boost::archive::text_oarchive out(ss);
        f.serialize(out);   // File::serialize starts with the filetype, which Index::read consumes itself
    }
    NfsControlFile g;
    {
        boost::archive::text_iarchive in(ss);
        std::string type;
        in >> type;
        REQUIRE(type == "nfscontrol");
        g.deserialize(in);
    }

    REQUIRE(g.getFilename() == "2-0_NFS.control");   // VirtualFile prefixes <fragment id>-<start>_
    REQUIRE(g.getIdInIndex() == 5);
    REQUIRE(g.getFilesizeProcessed() == 123);
    REQUIRE(g.fragments.size() == 1);
    REQUIRE(g.fragments.at(0).id == 2);
    REQUIRE(g.fragments.at(0).length == 4096);
    REQUIRE(g.tcpBreaks.size() == 3);
    REQUIRE(g.tcpBreaks == f.tcpBreaks);
}


TEST_CASE("NFS stream: xids are matched per call direction", "[nfs]") {
    const TimePoint t0{};
    const Buf clientCall = compoundCall(0x42, 24);
    const Buf serverCall = compoundCall(0x42, 24);      // callback on the same connection, same xid
    const Buf clientReply = compoundReply(0x42, 24);    // sent by the client, answers the server's call
    const Buf serverReply = compoundReply(0x42, 24);    // sent by the server, answers the client's call
    Buf stream;
    std::vector<std::pair<uint64_t, TimePoint>> breaks;
    // chunk index parity gives the direction: even = client, odd = server
    breaks.emplace_back(stream.size(), t0 + std::chrono::milliseconds(1)); append(stream, clientCall);
    breaks.emplace_back(stream.size(), t0 + std::chrono::milliseconds(2)); append(stream, serverCall);
    breaks.emplace_back(stream.size(), t0 + std::chrono::milliseconds(3)); append(stream, clientReply);
    breaks.emplace_back(stream.size(), t0 + std::chrono::milliseconds(4)); append(stream, serverReply);
    const NfsStream s = parseNfsStream(stream.data(), stream.size(), breaks);
    REQUIRE(s.messages.size() == 4);
    CHECK(s.messages[0].record.direction == 0);
    CHECK(s.messages[1].record.direction == 1);
    CHECK_FALSE(s.messages[1].retransmission);
    CHECK(s.messages[0].matchedIndex == 3);
    CHECK(s.messages[3].matchedIndex == 0);
    CHECK(s.messages[1].matchedIndex == 2);
    CHECK(s.messages[2].matchedIndex == 1);
    CHECK_FALSE(s.messages[2].retransmission);
    CHECK_FALSE(s.messages[3].retransmission);
}

TEST_CASE("NFS stream: oversized fragments and records are garbage", "[nfs]") {
    const TimePoint t0{};
    const std::vector<std::pair<uint64_t, TimePoint>> breaks{{0, t0 + std::chrono::milliseconds(1)}};
    const NfsStreamLimits defaults;
    CHECK(defaults.maxFragment == 64u << 20);
    CHECK(defaults.maxRecord == 256ull << 20);

    SECTION("a record mark above the default fragment limit") {
        Buf stream;
        put32(stream, 0x80000000u | ((64u << 20) + 1));
        stream.resize(stream.size() + 64, 0xAA);
        const NfsStream s = parseNfsStream(stream.data(), stream.size(), breaks);
        REQUIRE(s.messages.size() == 1);
        CHECK(garbageRecords(s) == 1);
    }

    SECTION("a fragment of exactly the limit is accepted") {
        NfsStreamLimits limits;
        limits.maxFragment = 32;
        Buf stream;
        put32(stream, 0x80000000u | 32);
        stream.resize(stream.size() + 32, 0);
        const NfsStream s = parseNfsStream(stream.data(), stream.size(), breaks, limits);
        CHECK(garbageRecords(s) == 0);
    }

    SECTION("the reassembled record grows beyond the record limit") {
        NfsStreamLimits limits;
        limits.maxFragment = 64;
        limits.maxRecord = 100;
        Buf stream;
        for (int i = 0; i < 3; ++i) {           // 3 x 40 bytes, only the last fragment carries the last-fragment flag
            put32(stream, (i == 2 ? 0x80000000u : 0u) | 40);
            stream.resize(stream.size() + 40, 0x11);
        }
        const NfsStream s = parseNfsStream(stream.data(), stream.size(), breaks, limits);
        REQUIRE_FALSE(s.messages.empty());
        CHECK(garbageRecords(s) >= 1);
        CHECK(s.messages[0].record.garbage);
        CHECK(s.messages[0].record.bytes.empty());
    }
}
