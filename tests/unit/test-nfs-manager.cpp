#include <catch2/catch.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "../../src/virtualfiles/nfs/nfs_manager.h"
#include "nfs-test-utils.h"

using namespace pcapfs;
using namespace pcapfs::nfs;

namespace {
    const std::string SERVER = "10.0.0.1";

    TimePoint ms(int n) { return TimePoint(std::chrono::milliseconds(n)); }

    ArgOp putfh(const std::string &fh) { return {op::PUTFH, PutfhArgs{fh}}; }
    ArgOp simple(uint32_t o) { return {o, GenericArgs{}}; }
    ArgOp lookup(const std::string &name) { return {op::LOOKUP, NameArgs{name}}; }
    ArgOp getattr() { return {op::GETATTR, GenericArgs{}}; }
    ArgOp write(uint64_t offset, uint32_t length) {
        WriteArgs w;
        w.offset = offset;
        w.data = Span{0, length};
        return {op::WRITE, w};
    }

    ArgOp nameOp(uint32_t o, const std::string &name) { return {o, NameArgs{name}}; }
    ArgOp renameOp(const std::string &oldname, const std::string &newname) { return {op::RENAME, RenameArgs{oldname, newname}}; }
    ArgOp rangeOp(uint32_t o, uint64_t offset, uint64_t length) {
        RangeArgs r;
        r.offset = offset;
        r.length = length;
        return {o, r};
    }
    ArgOp read(uint64_t offset, uint32_t count) {
        ReadArgs r;
        r.offset = offset;
        r.count = count;
        return {op::READ, r};
    }

    ResOp ok(uint32_t o, ResVariant r = GenericRes{}) { return {o, NFS4_OK, std::move(r)}; }
    ResOp readRes(uint32_t count) { ReadRes r; r.data = Span{0, count}; return ok(op::READ, r); }
    std::vector<ResOp> allOk(const std::vector<ArgOp> &args) {
        std::vector<ResOp> r;
        for (const ArgOp &a : args)
            r.push_back(ok(a.op));
        return r;
    }

    // renders a version: fragment bytes become 'x', holes stay 0
    std::string render(const NfsVersion &v) {
        std::string buf(v.size, '\0');
        nfsReadContent(v.content, v.size, 0, buf.size(), buf.data(),
                       [](const Fragment &, uint64_t, size_t len, char *dst) { std::fill(dst, dst + len, 'x'); });
        return buf;
    }
    ResOp getfhRes(const std::string &fh) { return ok(op::GETFH, GetfhRes{fh}); }
    ResOp writeRes(uint32_t count) { WriteRes w; w.count = count; return ok(op::WRITE, w); }

    // builds the call (and optionally the reply) messages of a synthetic stream; the record payload
    // of a WRITE is the buffer range [bufferOffset, bufferOffset + dataLength)
    class StreamBuilder {
    public:
        void add(int timeMs, std::vector<ArgOp> args, std::optional<std::vector<ResOp>> results,
                 uint64_t bufferOffset = 0, uint64_t dataLength = 0) {
            NfsMessage call;
            call.index = stream.messages.size();
            call.isCall = true;
            call.isNfs4 = true;
            call.record.time = ms(timeMs);
            if (dataLength)
                call.record.pieces.push_back({bufferOffset, dataLength});
            CompoundArgs ca;
            ca.ops = std::move(args);
            ca.complete = true;
            call.args = std::move(ca);
            if (results)
                call.matchedIndex = call.index + 1;
            stream.messages.push_back(std::move(call));
            if (results) {
                NfsMessage reply;
                reply.index = stream.messages.size();
                reply.isNfs4 = true;
                reply.record.time = ms(timeMs);
                reply.record.direction = 1;
                reply.matchedIndex = reply.index - 1;
                CompoundRes cr;
                cr.ops = std::move(*results);
                cr.complete = true;
                reply.res = std::move(cr);
                stream.messages.push_back(std::move(reply));
            }
        }

        // registry as filled by replayStreams; replay() is too slow for the deep-chain tests
        ServerFileRegistry replayRegistry() {
            ReplayStream rs;
            rs.tcpId = 7;
            rs.srcIP = "10.0.0.2"; rs.dstIP = SERVER; rs.srcPort = "1000"; rs.dstPort = "2049";
            rs.stream = std::move(stream);
            rs.ep.serverIP = SERVER;
            rs.ep.clientIP = "10.0.0.2";
            rs.ep.valid = true;
            std::vector<ReplayStream> streams;
            streams.push_back(std::move(rs));
            ServerFileRegistry registry;
            uint64_t next = 1;
            replayStreams(streams, registry, [&next] { return next++; });
            return registry;
        }

        std::map<std::string, NfsFilePtr> replay() {
            ServerFileRegistry registry = replayRegistry();
            std::map<std::string, NfsFilePtr> result;
            for (auto &entry : registry[SERVER_FILE_TREE_DUMMY]) {
                NfsFilePtr f = std::static_pointer_cast<NfsFile>(entry.second);
                std::string path = f->getFilename();
                for (FilePtr p = f->getParentDir(); p; p = std::static_pointer_cast<NfsFile>(p)->getParentDir())
                    path = p->getFilename() + "/" + path;
                result[path] = f;
            }
            return result;
        }

        NfsStream stream;
    };

    std::vector<std::string> childNames(const std::map<std::string, NfsFilePtr> &files, const std::string &dir) {
        std::vector<std::string> names;
        for (const auto &e : files) {
            if (e.first.size() > dir.size() + 1 && e.first.compare(0, dir.size() + 1, dir + "/") == 0 &&
                e.first.find('/', dir.size() + 1) == std::string::npos)
                names.push_back(e.first.substr(dir.size() + 1));
        }
        return names;
    }
}

TEST_CASE("NFS merge keeps the content of a child whose name collides", "[nfs]") {
    StreamBuilder b;
    // d/x gets content
    b.add(1, {simple(op::PUTROOTFH), lookup("d"), lookup("x"), write(0, 5)},
          std::vector<ResOp>{ok(op::PUTROOTFH), ok(op::LOOKUP), ok(op::LOOKUP), writeRes(5)}, 0, 5);
    // orphan directory "A" with an (empty) child of the same name
    b.add(2, {putfh("A"), lookup("x")}, std::vector<ResOp>{ok(op::PUTFH), ok(op::LOOKUP)});
    // d turns out to be "A"
    b.add(3, {simple(op::PUTROOTFH), lookup("d"), simple(op::GETFH)},
          std::vector<ResOp>{ok(op::PUTROOTFH), ok(op::LOOKUP), getfhRes("A")});
    const auto files = b.replay();

    REQUIRE(files.count(SERVER + "/d/x"));
    const NfsFilePtr x = files.at(SERVER + "/d/x");
    REQUIRE(x->versions.size() == 1);
    CHECK(x->versions.back().size == 5);
    CHECK_FALSE(x->versions.back().content.empty());
    // nothing was left behind as an unknown-* orphan
    CHECK(childNames(files, SERVER) == std::vector<std::string>{"d"});
}

TEST_CASE("NFS orphans with a common filehandle prefix get distinct names", "[nfs]") {
    StreamBuilder b;
    const std::string prefix("\x01\x00\x07\x01", 4);
    b.add(1, {putfh(prefix + "AAAA"), write(0, 3)}, std::vector<ResOp>{ok(op::PUTFH), writeRes(3)}, 0, 3);
    b.add(2, {putfh(prefix + "BBBB"), write(0, 3)}, std::vector<ResOp>{ok(op::PUTFH), writeRes(3)}, 10, 3);
    const auto files = b.replay();
    const auto names = childNames(files, SERVER);
    REQUIRE(names.size() == 2);
    CHECK(names[0] != names[1]);
    CHECK(names[0].rfind("unknown-", 0) == 0);
}

TEST_CASE("NFS PUTFH(rootfh) before PUTROOTFH+GETFH keeps the root and its children", "[nfs]") {
    StreamBuilder b;
    b.add(1, {putfh("R"), lookup("a")}, std::vector<ResOp>{ok(op::PUTFH), ok(op::LOOKUP)});
    b.add(2, {simple(op::PUTROOTFH), simple(op::GETFH)}, std::vector<ResOp>{ok(op::PUTROOTFH), getfhRes("R")});
    b.add(3, {simple(op::PUTROOTFH), lookup("b")}, std::vector<ResOp>{ok(op::PUTROOTFH), ok(op::LOOKUP)});
    const auto files = b.replay();
    REQUIRE(files.count(SERVER));
    CHECK(files.at(SERVER)->isDirectory);
    CHECK(childNames(files, SERVER) == (std::vector<std::string>{"a", "b"}));
}

TEST_CASE("NFS merged versions are in chronological order", "[nfs]") {
    StreamBuilder b;
    // named node n written first (t=1), orphan "A" written later (t=2), then n is identified as "A"
    b.add(1, {simple(op::PUTROOTFH), lookup("n"), write(0, 3)},
          std::vector<ResOp>{ok(op::PUTROOTFH), ok(op::LOOKUP), writeRes(3)}, 0, 3);
    b.add(2, {putfh("A"), write(0, 4)}, std::vector<ResOp>{ok(op::PUTFH), writeRes(4)}, 10, 4);
    b.add(3, {simple(op::PUTROOTFH), lookup("n"), simple(op::GETFH)},
          std::vector<ResOp>{ok(op::PUTROOTFH), ok(op::LOOKUP), getfhRes("A")});
    const auto files = b.replay();
    REQUIRE(files.count(SERVER + "/n"));
    const NfsFilePtr n = files.at(SERVER + "/n");
    REQUIRE(n->versions.size() == 2);
    CHECK(n->versions[0].networkStart <= n->versions[1].networkStart);
    CHECK(n->versions[0].size == 3);
    CHECK(n->versions[1].size == 4);
}

TEST_CASE("NFS compound without reply applies a WRITE behind GETATTR", "[nfs]") {
    StreamBuilder b;
    // every WRITE of the compound is applied, not only the first one
    b.add(1, {putfh("F"), getattr(), write(0, 6), getattr(), write(6, 6)}, std::nullopt, 0, 12);
    const auto files = b.replay();
    const auto names = childNames(files, SERVER);
    REQUIRE(names.size() == 1);
    const NfsFilePtr f = files.at(SERVER + "/" + names[0]);
    REQUIRE(f->versions.size() == 1);
    CHECK(f->versions.back().size == 12);
    CHECK_FALSE(f->versions.back().content.empty());
}

TEST_CASE("NFS compound without reply navigates with LOOKUPP through known nodes", "[nfs]") {
    StreamBuilder b;
    b.add(1, {simple(op::PUTROOTFH), lookup("d"), lookup("x")}, std::vector<ResOp>{ok(op::PUTROOTFH), ok(op::LOOKUP), ok(op::LOOKUP)});
    b.add(2, {simple(op::PUTROOTFH), lookup("d"), lookup("y")}, std::vector<ResOp>{ok(op::PUTROOTFH), ok(op::LOOKUP), ok(op::LOOKUP)});
    // d/x -> LOOKUPP -> d -> y, then WRITE into d/y; a later OPEN by name stops the replay
    b.add(3, {simple(op::PUTROOTFH), lookup("d"), lookup("x"), simple(op::LOOKUPP), lookup("y"), write(0, 4),
              ArgOp{op::OPEN, OpenArgs{}}, write(0, 9)}, std::nullopt, 0, 4);
    const auto files = b.replay();
    REQUIRE(files.count(SERVER + "/d/y"));
    REQUIRE(files.at(SERVER + "/d/y")->versions.size() == 1);
    CHECK(files.at(SERVER + "/d/y")->versions.back().size == 4);
    REQUIRE(files.count(SERVER + "/d/x"));
    CHECK(files.at(SERVER + "/d/x")->versions.empty());
    CHECK(childNames(files, SERVER) == std::vector<std::string>{"d"});
}

TEST_CASE("NFS hard links share the content of their source", "[nfs]") {
    StreamBuilder b;
    // a gets fh F and 5 bytes
    b.add(1, {simple(op::PUTROOTFH), lookup("a"), simple(op::GETFH), write(0, 5)},
          std::vector<ResOp>{ok(op::PUTROOTFH), ok(op::LOOKUP), getfhRes("F"), writeRes(5)}, 0, 5);
    // LINK: sfh = a, cfh = root, newname b
    const std::vector<ArgOp> linkOps{simple(op::PUTROOTFH), lookup("a"), simple(op::SAVEFH), simple(op::PUTROOTFH), nameOp(op::LINK, "b")};
    b.add(2, linkOps, allOk(linkOps));
    // on Linux knfsd the link resolves to the same filehandle (and fileid)
    b.add(3, {simple(op::PUTROOTFH), lookup("b"), simple(op::GETFH)},
          std::vector<ResOp>{ok(op::PUTROOTFH), ok(op::LOOKUP), getfhRes("F")});

    SECTION("both names show identical content") {
        const auto files = b.replay();
        CHECK(childNames(files, SERVER) == (std::vector<std::string>{"a", "b"}));
        const NfsFilePtr a = files.at(SERVER + "/a");
        const NfsFilePtr bb = files.at(SERVER + "/b");
        CHECK(a != bb);
        REQUIRE(a->versions.size() == 1);
        REQUIRE(bb->versions.size() == 1);
        CHECK(bb->versions.back().size == 5);
        CHECK(nfsContentEqual(a->versions.back().content, bb->versions.back().content));
        CHECK_FALSE(bb->flags.test(pcapfs::flags::IS_METADATA));
        CHECK(a->getIdInIndex() != bb->getIdInIndex());
    }
    SECTION("a WRITE through the link is visible under both names") {
        b.add(4, {simple(op::PUTROOTFH), lookup("b"), write(5, 3)},
              std::vector<ResOp>{ok(op::PUTROOTFH), ok(op::LOOKUP), writeRes(3)}, 10, 3);
        const auto files = b.replay();
        REQUIRE(files.at(SERVER + "/a")->versions.size() == 1);
        CHECK(files.at(SERVER + "/a")->versions.back().size == 8);
        CHECK(files.at(SERVER + "/b")->versions.back().size == 8);
        CHECK(nfsContentEqual(files.at(SERVER + "/a")->versions.back().content, files.at(SERVER + "/b")->versions.back().content));
    }
    SECTION("REMOVE of the original name keeps the link's content") {
        b.add(4, {simple(op::PUTROOTFH), nameOp(op::REMOVE, "a")}, std::vector<ResOp>{ok(op::PUTROOTFH), ok(op::REMOVE)});
        const auto files = b.replay();
        REQUIRE(files.count(SERVER + "/a"));
        REQUIRE(files.count(SERVER + "/b"));
        CHECK(files.at(SERVER + "/a")->deleted);
        CHECK_FALSE(files.at(SERVER + "/b")->deleted);
        REQUIRE(files.at(SERVER + "/b")->versions.size() == 1);
        CHECK(files.at(SERVER + "/b")->versions.back().size == 5);
        CHECK_FALSE(files.at(SERVER + "/b")->flags.test(pcapfs::flags::IS_METADATA));
    }
}

TEST_CASE("NFS DEALLOCATE punches a hole, ALLOCATE grows the file", "[nfs]") {
    StreamBuilder b;
    b.add(1, {putfh("F"), write(0, 100)}, std::vector<ResOp>{ok(op::PUTFH), writeRes(100)}, 0, 100);

    SECTION("DEALLOCATE right after the WRITE stays in the same version") {
        b.add(2, {putfh("F"), rangeOp(op::DEALLOCATE, 20, 20)}, std::vector<ResOp>{ok(op::PUTFH), ok(op::DEALLOCATE)});
        const auto files = b.replay();
        const auto names = childNames(files, SERVER);
        REQUIRE(names.size() == 1);
        const NfsFilePtr f = files.at(SERVER + "/" + names[0]);
        REQUIRE(f->versions.size() == 1);
        CHECK(f->versions.back().size == 100);
        CHECK(render(f->versions.back()) == std::string(20, 'x') + std::string(20, '\0') + std::string(60, 'x'));
    }
    SECTION("DEALLOCATE after a READ starts a new version, ALLOCATE within the size changes nothing") {
        b.add(2, {putfh("F"), read(0, 100)}, std::vector<ResOp>{ok(op::PUTFH), readRes(100)});
        b.add(3, {putfh("F"), rangeOp(op::DEALLOCATE, 20, 20)}, std::vector<ResOp>{ok(op::PUTFH), ok(op::DEALLOCATE)});
        b.add(4, {putfh("F"), rangeOp(op::ALLOCATE, 0, 50)}, std::vector<ResOp>{ok(op::PUTFH), ok(op::ALLOCATE)});   // no-op
        const auto files = b.replay();
        const auto names = childNames(files, SERVER);
        REQUIRE(names.size() == 1);
        const NfsFilePtr f = files.at(SERVER + "/" + names[0]);
        REQUIRE(f->versions.size() == 2);
        CHECK(f->versions[0].size == 100);
        CHECK(render(f->versions[0]) == std::string(100, 'x'));
        CHECK(f->versions[1].size == 100);
        CHECK(render(f->versions[1]) == std::string(20, 'x') + std::string(20, '\0') + std::string(60, 'x'));
    }
    SECTION("ALLOCATE beyond the size after a READ grows the file in a new version") {
        b.add(2, {putfh("F"), read(0, 100)}, std::vector<ResOp>{ok(op::PUTFH), readRes(100)});
        b.add(3, {putfh("F"), rangeOp(op::ALLOCATE, 90, 30)}, std::vector<ResOp>{ok(op::PUTFH), ok(op::ALLOCATE)});
        const auto files = b.replay();
        const auto names = childNames(files, SERVER);
        REQUIRE(names.size() == 1);
        const NfsFilePtr g = files.at(SERVER + "/" + names[0]);
        REQUIRE(g->versions.size() == 2);
        CHECK(g->versions[0].size == 100);
        CHECK(g->versions[1].size == 120);
        CHECK(render(g->versions[1]) == std::string(100, 'x') + std::string(20, '\0'));
    }
    SECTION("DEALLOCATE without reply is applied like a WRITE") {
        b.add(2, {putfh("F"), getattr(), rangeOp(op::DEALLOCATE, 0, 10)}, std::nullopt);
        const auto files = b.replay();
        const auto names = childNames(files, SERVER);
        REQUIRE(names.size() == 1);
        const NfsFilePtr f = files.at(SERVER + "/" + names[0]);
        REQUIRE(f->versions.size() == 1);
        CHECK(render(f->versions.back()) == std::string(10, '\0') + std::string(90, 'x'));
    }
}

TEST_CASE("NFS RENAME into its own subtree is ignored", "[nfs]") {
    StreamBuilder b;
    b.add(1, {simple(op::PUTROOTFH), lookup("a"), lookup("b")}, std::vector<ResOp>{ok(op::PUTROOTFH), ok(op::LOOKUP), ok(op::LOOKUP)});
    // sfh = root, cfh = a/b: moving a below a/b would create a cycle
    const std::vector<ArgOp> ops{simple(op::PUTROOTFH), simple(op::SAVEFH), lookup("a"), lookup("b"), renameOp("a", "c")};
    b.add(2, ops, allOk(ops));
    const auto files = b.replay();
    CHECK(files.count(SERVER + "/a/b"));
    CHECK(childNames(files, SERVER) == std::vector<std::string>{"a"});
    CHECK(childNames(files, SERVER + "/a") == std::vector<std::string>{"b"});
}

TEST_CASE("NFS filehandle change to an orphan ancestor does not create a cycle", "[nfs]") {
    StreamBuilder b;
    b.add(1, {putfh("O"), lookup("p"), lookup("q"), simple(op::GETFH)},
          std::vector<ResOp>{ok(op::PUTFH), ok(op::LOOKUP), ok(op::LOOKUP), getfhRes("Q")});
    // q now reports the filehandle of its orphan grandparent O: O must not be moved below p
    b.add(2, {putfh("O"), lookup("p"), lookup("q"), simple(op::GETFH)},
          std::vector<ResOp>{ok(op::PUTFH), ok(op::LOOKUP), ok(op::LOOKUP), getfhRes("O")});
    const auto files = b.replay();
    const auto top = childNames(files, SERVER);
    REQUIRE(top.size() == 1);
    CHECK(top[0].rfind("unknown-", 0) == 0);
    CHECK(childNames(files, SERVER + "/" + top[0]) == std::vector<std::string>{"p"});
    CHECK(files.count(SERVER + "/" + top[0] + "/p/q"));
    CHECK(files.at(SERVER + "/" + top[0] + "/p/q")->deleted);
    CHECK(files.size() == 4);
}

TEST_CASE("NFS orphan subtrees are emitted once even if a child node is older than its parent", "[nfs]") {
    StreamBuilder b;
    b.add(1, {simple(op::PUTROOTFH), lookup("x")}, std::vector<ResOp>{ok(op::PUTROOTFH), ok(op::LOOKUP)});
    b.add(2, {putfh("A")}, std::vector<ResOp>{ok(op::PUTFH)});
    // x (created before the orphan A) is moved below A: s.nodes lists the child before its parent
    const std::vector<ArgOp> ops{simple(op::PUTROOTFH), simple(op::SAVEFH), putfh("A"), renameOp("x", "y")};
    b.add(3, ops, allOk(ops));
    const auto files = b.replay();
    const auto top = childNames(files, SERVER);
    REQUIRE(top.size() == 1);
    CHECK(top[0].rfind("unknown-", 0) == 0);
    CHECK(childNames(files, SERVER + "/" + top[0]) == std::vector<std::string>{"y"});
    CHECK(files.size() == 3);   // root, A, y: no second registration of y
}

TEST_CASE("NFS timestamps outside the representable range are clamped", "[nfs]") {
    const auto attrsRes = [](int64_t seconds) {
        Fattr4 a;
        a.timeModify = Nfstime4{seconds, 999999999};
        a.timeMetadata = Nfstime4{seconds, 999999999};
        return ok(op::GETATTR, GetattrRes{a});
    };
    StreamBuilder b;
    b.add(1000, {putfh("F"), getattr()}, std::vector<ResOp>{ok(op::PUTFH), attrsRes(std::numeric_limits<int64_t>::max())});
    b.add(2000, {putfh("G"), getattr()}, std::vector<ResOp>{ok(op::PUTFH), attrsRes(std::numeric_limits<int64_t>::min())});
    const auto files = b.replay();
    REQUIRE(childNames(files, SERVER).size() == 2);
    // clamped to 8 s inside the range of TimePoint, the nanoseconds are kept
    const int64_t limit = std::chrono::duration_cast<std::chrono::seconds>(TimePoint::duration::max()).count() - 8;
    const auto clamped = [](int64_t seconds) {
        return TimePoint(std::chrono::duration_cast<TimePoint::duration>(std::chrono::seconds(seconds) +
                                                                         std::chrono::nanoseconds(999999999)));
    };
    std::set<TimePoint> modifyTimes;
    for (const auto &entry : files) {
        if (entry.second->nodeFs.modifyTime != TimePoint{})
            modifyTimes.insert(entry.second->nodeFs.modifyTime);
    }
    CHECK(modifyTimes == std::set<TimePoint>{clamped(limit), clamped(-limit)});
}

TEST_CASE("NFS replay records fs time history, READ accesses and the server skew", "[nfs]") {
    const auto attrsRes = [](int64_t modifySeconds, int64_t metadataSeconds) {
        Fattr4 a;
        a.timeModify = Nfstime4{modifySeconds, 0};
        a.timeMetadata = Nfstime4{metadataSeconds, 0};
        return ok(op::GETATTR, GetattrRes{a});
    };

    StreamBuilder b;
    // network time 1 s, server clock 1000 s ahead: WRITE + GETATTR in one compound give the skew
    b.add(1000, {putfh("F"), write(0, 6), getattr()}, std::vector<ResOp>{ok(op::PUTFH), writeRes(6), attrsRes(1001, 1001)}, 0, 6);
    b.add(2000, {putfh("F"), write(0, 6), getattr()}, std::vector<ResOp>{ok(op::PUTFH), writeRes(6), attrsRes(1002, 1002)}, 0, 6);
    b.add(3000, {putfh("F"), write(0, 6), getattr()}, std::vector<ResOp>{ok(op::PUTFH), writeRes(6), attrsRes(1003, 1003)}, 0, 6);
    b.add(4000, {putfh("F"), read(0, 6)}, std::vector<ResOp>{ok(op::PUTFH), readRes(6)}, 0, 6);
    const auto files = b.replay();
    const auto names = childNames(files, SERVER);
    REQUIRE(names.size() == 1);
    const NfsFilePtr f = files.at(SERVER + "/" + names[0]);
    REQUIRE(f->versions.size() == 1);
    const NfsVersion &v = f->versions.front();
    CHECK(v.accesses == std::set<TimePoint>{ms(4000)});
    // history keeps the first and the latest GETATTR, keyed by the compound's network time
    REQUIRE(v.fsHistory.size() == 2);
    CHECK(v.fsHistory.begin()->first == ms(1000));
    CHECK(v.fsHistory.begin()->second.modifyTime == TimePoint(std::chrono::seconds(1001)));
    CHECK(v.fsHistory.rbegin()->first == ms(3000));
    CHECK(v.fsHistory.rbegin()->second.modifyTime == TimePoint(std::chrono::seconds(1003)));
    CHECK(f->nodeFsHistory.size() == 2);
    CHECK(f->observations.count(ms(4000)) == 1);
    CHECK(f->skew == std::chrono::seconds(1000));
}

TEST_CASE("NFS replay ignores a retransmitted copy of a call", "[nfs]") {
    StreamBuilder b;
    b.add(1, {simple(op::PUTROOTFH), lookup("n"), write(0, 5)},
          std::vector<ResOp>{ok(op::PUTROOTFH), ok(op::LOOKUP), writeRes(5)}, 0, 5);
    NfsMessage copy = b.stream.messages[0];
    copy.index = b.stream.messages.size();
    copy.retransmission = true;
    copy.matchedIndex.reset();
    b.stream.messages.push_back(std::move(copy));
    const auto files = b.replay();
    REQUIRE(files.count(SERVER + "/n"));
    const NfsFilePtr f = files.at(SERVER + "/n");
    REQUIRE(f->versions.size() == 1);
    CHECK(f->versions[0].size == 5);
}

TEST_CASE("NFS replay does not apply a call the server rejected on the RPC level", "[nfs]") {
    const auto rejected = [](uint32_t replyStat, uint32_t acceptStat) {
        StreamBuilder b;
        b.add(1, {simple(op::PUTROOTFH), lookup("n"), write(0, 5)},
              std::vector<ResOp>{ok(op::PUTROOTFH), ok(op::LOOKUP), writeRes(5)}, 0, 5);
        // second WRITE: the reply carries no COMPOUND result because the RPC layer refused the call
        b.add(2, {simple(op::PUTROOTFH), lookup("n"), write(5, 5)}, std::vector<ResOp>{}, 5, 5);
        NfsMessage &reply = b.stream.messages.back();
        reply.res.reset();
        RpcReply header;
        header.replyStat = replyStat;
        header.acceptStat = acceptStat;
        reply.reply = header;
        return b.replay();
    };
    for (const auto &files : {rejected(MSG_DENIED, 0), rejected(MSG_ACCEPTED, 4 /* GARBAGE_ARGS */)}) {
        REQUIRE(files.count(SERVER + "/n"));
        const NfsFilePtr f = files.at(SERVER + "/n");
        REQUIRE(f->versions.size() == 1);
        CHECK(f->versions[0].size == 5);
    }
}

TEST_CASE("NFS replay applies the WRITE of a call whose reply is missing", "[nfs]") {
    StreamBuilder b;
    b.add(1, {simple(op::PUTROOTFH), lookup("n"), write(0, 5)},
          std::vector<ResOp>{ok(op::PUTROOTFH), ok(op::LOOKUP), writeRes(5)}, 0, 5);
    b.add(2, {simple(op::PUTROOTFH), lookup("n"), write(5, 5)}, std::nullopt, 5, 5);
    const auto files = b.replay();
    REQUIRE(files.count(SERVER + "/n"));
    CHECK(files.at(SERVER + "/n")->versions.back().size == 10);
}

TEST_CASE("NFS ignores WRITEs whose offset plus length wraps", "[nfs]") {
    StreamBuilder b;
    b.add(1, {simple(op::PUTROOTFH), lookup("w"), write(0xFFFFFFFFFFFFFF00ULL, 4096)},
          std::vector<ResOp>{ok(op::PUTROOTFH), ok(op::LOOKUP), writeRes(4096)}, 0, 4096);
    b.add(2, {simple(op::PUTROOTFH), lookup("w"), write(0, 6)},
          std::vector<ResOp>{ok(op::PUTROOTFH), ok(op::LOOKUP), writeRes(6)}, 0, 6);
    const auto files = b.replay();
    REQUIRE(files.count(SERVER + "/w"));
    const NfsFilePtr f = files.at(SERVER + "/w");
    REQUIRE(f->versions.size() == 1);
    CHECK(f->versions[0].size == 6);
    CHECK(f->versions[0].content.size() == 1);
}

TEST_CASE("NFS names from the wire are made safe path components", "[nfs]") {
    StreamBuilder b;
    int t = 1;
    for (const std::string name : {"a/b", "..", ".", "", "a_b"}) {
        b.add(t++, {simple(op::PUTROOTFH), lookup(name), write(0, 3)},
              std::vector<ResOp>{ok(op::PUTROOTFH), ok(op::LOOKUP), writeRes(3)}, 0, 3);
    }
    const auto files = b.replay();
    std::vector<std::string> names = childNames(files, SERVER);
    std::sort(names.begin(), names.end());
    CHECK(names == std::vector<std::string>{"_dot_", "_dotdot_", "_empty_", "a_b", "a_b-2"});
    for (const auto &e : files)
        CHECK(std::count(e.first.begin(), e.first.end(), '/') <= 2);
}


namespace {
    // the placements of a replayed file: (since in ms, parent id, name)
    std::string placementString(const NfsFile &f) {
        std::string out;
        for (const NfsPlacement &p : f.placements)
            out += "[" + std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(p.since.time_since_epoch()).count()) +
                   " " + std::to_string(p.parentId) + " " + p.name + "]";
        return out;
    }

    std::map<uint64_t, FilePtr> filesById(const std::map<std::string, NfsFilePtr> &files) {
        std::map<uint64_t, FilePtr> byId;
        for (const auto &e : files)
            byId[e.second->getIdInIndex()] = e.second;
        return byId;
    }

    std::string pathOf(const FilePtr &file) {
        std::string path = file->getFilename();
        for (FilePtr p = std::static_pointer_cast<NfsFile>(file)->getParentDir(); p;
             p = std::static_pointer_cast<NfsFile>(p)->getParentDir())
            path = p->getFilename() + "/" + path;
        return path;
    }
}

TEST_CASE("NFS RENAME records placements and snapshots place the file before and after it", "[nfs]") {
    nfstest::ConfigGuard guard;
    guard.mode(options::TimestampMode::NETWORK);

    StreamBuilder b;
    // dir1/sub/large (fh F) and dir1 (fh D1), sub (fh S); all seen at t=10..30 ms
    b.add(10, {simple(op::PUTROOTFH), lookup("dir1"), simple(op::GETFH), lookup("sub"), simple(op::GETFH), lookup("large"), simple(op::GETFH), write(0, 5)},
          std::vector<ResOp>{ok(op::PUTROOTFH), ok(op::LOOKUP), getfhRes("D1"), ok(op::LOOKUP), getfhRes("S"), ok(op::LOOKUP), getfhRes("F"), writeRes(5)}, 0, 5);
    // mv dir1/sub/large dir1/renamed (sfh = sub, cfh = dir1) at t=100
    const std::vector<ArgOp> mv{simple(op::PUTROOTFH), lookup("dir1"), lookup("sub"), simple(op::SAVEFH), simple(op::PUTROOTFH), lookup("dir1"), renameOp("large", "renamed")};
    b.add(100, mv, allOk(mv));
    // mv dir1/sub dir1/sub2 (directory rename) at t=200
    const std::vector<ArgOp> mvDir{simple(op::PUTROOTFH), lookup("dir1"), simple(op::SAVEFH), renameOp("sub", "sub2")};
    b.add(200, mvDir, allOk(mvDir));
    const auto files = b.replay();

    const std::string base = SERVER;
    REQUIRE(files.count(base + "/dir1/renamed"));
    REQUIRE(files.count(base + "/dir1/sub2"));
    const NfsFilePtr large = files.at(base + "/dir1/renamed");
    const NfsFilePtr dir1 = files.at(base + "/dir1");
    const NfsFilePtr sub = files.at(base + "/dir1/sub2");
    const NfsFilePtr root = files.at(base);

    SECTION("placements") {
        const std::string d1 = std::to_string(dir1->getIdInIndex());
        const std::string sb = std::to_string(sub->getIdInIndex());
        CHECK(placementString(*large) == "[10 " + sb + " large][100 " + d1 + " renamed]");
        CHECK(placementString(*sub) == "[10 " + d1 + " sub][200 " + d1 + " sub2]");
        CHECK(placementString(*dir1) == "[10 " + std::to_string(root->getIdInIndex()) + " dir1]");
        CHECK(large->createdInCapture == false);
        CHECK(root->placements.empty());
        // the last placement is the materialized name and parent
        CHECK(large->placements.back().name == large->getFilename());
        CHECK(static_cast<uint64_t>(large->placements.back().parentId) == large->getParentDirId());
    }
    SECTION("snapshots") {
        const auto byId = filesById(files);
        for (const auto &e : files)
            e.second->setPlacementMap(&byId);
        guard.snapshotAt(ms(50));
        large->constructSnapshotFile();
        sub->constructSnapshotFile();
        CHECK(pathOf(large) == base + "/dir1/sub/large");
        guard.snapshotAt(ms(150));
        large->constructSnapshotFile();
        sub->constructSnapshotFile();
        CHECK(pathOf(large) == base + "/dir1/renamed");         // moved out of sub
        guard.snapshotAt(ms(250));
        large->constructSnapshotFile();
        sub->constructSnapshotFile();
        CHECK(pathOf(large) == base + "/dir1/renamed");
        CHECK(pathOf(sub) == base + "/dir1/sub2");
        guard.snapshotAt(ms(150));
        sub->constructSnapshotFile();
        CHECK(pathOf(sub) == base + "/dir1/sub");
    }
}

TEST_CASE("NFS hard link names come into existence with the LINK", "[nfs]") {
    nfstest::ConfigGuard guard;
    guard.mode(options::TimestampMode::NETWORK);

    StreamBuilder b;
    b.add(10, {simple(op::PUTROOTFH), lookup("a"), simple(op::GETFH), write(0, 5)},
          std::vector<ResOp>{ok(op::PUTROOTFH), ok(op::LOOKUP), getfhRes("F"), writeRes(5)}, 0, 5);
    b.add(20, {simple(op::PUTROOTFH), lookup("a"), read(0, 5)},
          std::vector<ResOp>{ok(op::PUTROOTFH), ok(op::LOOKUP), readRes(5)});
    const std::vector<ArgOp> linkOps{simple(op::PUTROOTFH), lookup("a"), simple(op::SAVEFH), simple(op::PUTROOTFH), nameOp(op::LINK, "b")};
    b.add(100, linkOps, allOk(linkOps));
    const auto files = b.replay();
    const NfsFilePtr a = files.at(SERVER + "/a");
    const NfsFilePtr link = files.at(SERVER + "/b");
    const auto byId = filesById(files);
    a->setPlacementMap(&byId);
    link->setPlacementMap(&byId);

    SECTION("the clone has its own firstSeen, observations, placements and flag") {
        CHECK(link->firstSeen == ms(100));
        CHECK(*link->observations.begin() == ms(100));
        CHECK(a->firstSeen == ms(10));
        CHECK(a->observations.count(ms(20)) == 1);
        CHECK(link->createdInCapture);
        CHECK_FALSE(a->createdInCapture);
        CHECK(placementString(*link) == "[100 " + std::to_string(files.at(SERVER)->getIdInIndex()) + " b]");
        // the content (versions, accesses) is shared
        REQUIRE(link->versions.size() == 1);
        CHECK(link->versions.front().accesses.count(ms(20)) == 1);
    }
    SECTION("snapshot before the LINK hides the new name, the original stays") {
        guard.snapshotAt(ms(50));
        CHECK_FALSE(link->constructSnapshotFile());
        CHECK(a->constructSnapshotFile());
        guard.snapshotAt(ms(150));
        CHECK(link->constructSnapshotFile());
    }
    SECTION("a snip ending before the LINK does not show the new name") {
        guard.snip(std::nullopt, ms(90));
        CHECK(link->constructVersionFiles().empty());
        CHECK_FALSE(link->showFile());
        a->constructVersionFiles();
        CHECK(a->showFile());
    }
}

TEST_CASE("NFS merging nodes keeps the union of the placements", "[nfs]") {
    StreamBuilder b;
    // the file is first only known by its filehandle (WRITE through PUTFH), later found by name under another directory
    b.add(10, {putfh("F"), write(0, 4)}, std::vector<ResOp>{ok(op::PUTFH), writeRes(4)}, 0, 4);
    b.add(20, {simple(op::PUTROOTFH), lookup("d"), lookup("x"), simple(op::GETFH)},
          std::vector<ResOp>{ok(op::PUTROOTFH), ok(op::LOOKUP), ok(op::LOOKUP), getfhRes("F")});
    const std::vector<ArgOp> mv{simple(op::PUTROOTFH), lookup("d"), simple(op::SAVEFH), simple(op::PUTROOTFH), renameOp("x", "y")};
    b.add(30, mv, allOk(mv));
    const auto files = b.replay();
    REQUIRE(files.count(SERVER + "/y"));
    const NfsFile &f = *files.at(SERVER + "/y");
    // the nameless orphan contributes nothing: the first placement is the first time the name was seen
    REQUIRE(f.placements.size() == 2);
    CHECK(f.placements.front().since == ms(20));
    CHECK(f.placements.front().name == "x");
    CHECK(f.placements.back().name == "y");
    CHECK(f.versions.size() == 1);
}

TEST_CASE("NFS snapshots use plain names and append -2 to a clashing name", "[nfs]") {
    nfstest::ConfigGuard guard;
    guard.mode(options::TimestampMode::NETWORK);

    StreamBuilder b;
    // directory d (fh D1) is replaced by another object (fh D2) under the same name at t=50
    b.add(10, {simple(op::PUTROOTFH), lookup("d"), simple(op::GETFH)},
          std::vector<ResOp>{ok(op::PUTROOTFH), ok(op::LOOKUP), getfhRes("D1")});
    b.add(50, {simple(op::PUTROOTFH), lookup("d"), simple(op::GETFH)},
          std::vector<ResOp>{ok(op::PUTROOTFH), ok(op::LOOKUP), getfhRes("D2")});
    const auto files = b.replay();
    REQUIRE(files.count(SERVER + "/d@deleted"));
    REQUIRE(files.count(SERVER + "/d"));
    const NfsFilePtr oldDir = files.at(SERVER + "/d@deleted");
    const NfsFilePtr newDir = files.at(SERVER + "/d");
    // the final placements carry the plain wire name
    CHECK(oldDir->placements.back().name == "d");
    CHECK(newDir->placements.back().name == "d");

    const auto byId = filesById(files);
    for (const auto &e : files)
        e.second->setPlacementMap(&byId);

    SECTION("a snapshot inside the old node's lifetime shows the plain name, not @deleted") {
        guard.snapshotAt(ms(30));
        oldDir->applyPlacementAtSnapshot(byId);
        CHECK(oldDir->getFilename() == "d");
    }
    SECTION("two nodes sharing a name at the snapshot get the plain name and -2") {
        guard.snapshotAt(ms(30));
        std::vector<FilePtr> list{oldDir, newDir};
        for (const FilePtr &f : list)
            std::static_pointer_cast<NfsFile>(f)->applyPlacementAtSnapshot(byId);
        NfsManager::resolveSnapshotNames(list, byId);
        CHECK(oldDir->getFilename() == "d");        // earliest first placement
        CHECK(newDir->getFilename() == "d-2");
    }
}

TEST_CASE("NFS placement cycles at a snapshot fall back to the final placements", "[nfs]") {
    nfstest::ConfigGuard guard;
    guard.mode(options::TimestampMode::NETWORK);
    const auto make = [](uint64_t id, const std::string &name) {
        auto f = std::make_shared<NfsFile>();
        f->setIdInIndex(id);
        f->setFilename(name);
        f->setFiletype("nfs");
        f->isDirectory = true;
        return f;
    };
    const auto root = make(3, "root");
    const auto a = make(1, "a");
    const auto bb = make(2, "b");
    a->setParentDir(root);  a->setParentDirId(3);
    bb->setParentDir(root); bb->setParentDirId(3);
    // before t=20 the first placements put a below b and b below a
    a->placements = {{ms(1), 2, "a"}, {ms(20), 3, "a"}};
    bb->placements = {{ms(1), 1, "b"}, {ms(20), 3, "b"}};
    const std::map<uint64_t, FilePtr> byId{{1, a}, {2, bb}, {3, root}};
    guard.snapshotAt(ms(5));
    a->applyPlacementAtSnapshot(byId);
    bb->applyPlacementAtSnapshot(byId);
    REQUIRE(a->getParentDirId() == 2);
    REQUIRE(bb->getParentDirId() == 1);

    std::vector<FilePtr> list{a, bb, root};
    NfsManager::resolveSnapshotNames(list, byId);       // must terminate
    CHECK(a->getParentDirId() == 3);
    CHECK(bb->getParentDirId() == 3);
    CHECK(a->getFilename() == "a");
    CHECK(bb->getFilename() == "b");
    CHECK(a->getAllParentDirs().size() == 1);
}


TEST_CASE("NFS names with control bytes are made printable", "[nfs]") {
    StreamBuilder b;
    int t = 1;
    for (const std::string &name : {std::string("x\0y", 3), std::string("a\nb"), std::string("t\x7f\x1f" "z"), std::string("ok")}) {
        b.add(t++, {simple(op::PUTROOTFH), lookup(name), write(0, 3)},
              std::vector<ResOp>{ok(op::PUTROOTFH), ok(op::LOOKUP), writeRes(3)}, 0, 3);
    }
    const auto files = b.replay();
    std::vector<std::string> names = childNames(files, SERVER);
    std::sort(names.begin(), names.end());
    CHECK(names == std::vector<std::string>{"a_b", "ok", "t__z", "x_y"});
}

TEST_CASE("NFS reused filehandle after REMOVE is a new file", "[nfs]") {
    StreamBuilder b;
    const auto open = [](bool create, const std::string &name) {
        OpenArgs o;
        o.openType = create ? 1 : 0;
        o.claimType = 0;
        o.file = name;
        return ArgOp{op::OPEN, o};
    };
    b.add(1, {simple(op::PUTROOTFH), lookup("foo"), simple(op::GETFH), write(0, 3)},
          std::vector<ResOp>{ok(op::PUTROOTFH), ok(op::LOOKUP), getfhRes("FH1"), writeRes(3)}, 0, 3);
    b.add(2, {simple(op::PUTROOTFH), nameOp(op::REMOVE, "foo")}, std::vector<ResOp>{ok(op::PUTROOTFH), ok(op::REMOVE)});
    b.add(3, {simple(op::PUTROOTFH), open(true, "foo"), simple(op::GETFH)},
          std::vector<ResOp>{ok(op::PUTROOTFH), ok(op::OPEN, OpenRes{}), getfhRes("FH1")});
    b.add(4, {putfh("FH1"), write(0, 5)}, std::vector<ResOp>{ok(op::PUTFH), writeRes(5)}, 0, 5);
    const auto files = b.replay();
    REQUIRE(files.count(SERVER + "/foo"));
    REQUIRE(files.count(SERVER + "/foo@deleted"));
    CHECK(files.size() == 3);   // root, foo, foo@deleted: no orphan for the reused filehandle
    const NfsFilePtr fresh = files.at(SERVER + "/foo");
    const NfsFilePtr old = files.at(SERVER + "/foo@deleted");
    CHECK_FALSE(fresh->deleted);
    CHECK(old->deleted);
    REQUIRE(fresh->versions.size() == 1);
    CHECK(fresh->versions[0].size == 5);
    REQUIRE(old->versions.size() == 1);
    CHECK(old->versions[0].size == 3);
}

TEST_CASE("NFS filehandle of a removed name reused for another name", "[nfs]") {
    // name "a" has FH1 and is REMOVEd; FH1 is then handed to "b": no merge, "a" keeps its content
    StreamBuilder b;
    b.add(1, {simple(op::PUTROOTFH), lookup("a"), simple(op::GETFH), write(0, 3)},
          std::vector<ResOp>{ok(op::PUTROOTFH), ok(op::LOOKUP), getfhRes("FH1"), writeRes(3)}, 0, 3);
    b.add(2, {simple(op::PUTROOTFH), nameOp(op::REMOVE, "a")}, std::vector<ResOp>{ok(op::PUTROOTFH), ok(op::REMOVE)});
    b.add(3, {simple(op::PUTROOTFH), lookup("b"), simple(op::GETFH), write(0, 6)},
          std::vector<ResOp>{ok(op::PUTROOTFH), ok(op::LOOKUP), getfhRes("FH1"), writeRes(6)}, 0, 6);
    const auto files = b.replay();
    REQUIRE(files.count(SERVER + "/b"));
    REQUIRE(files.count(SERVER + "/a"));     // no live "a": the removed one keeps its plain name
    CHECK(files.at(SERVER + "/a")->deleted);
    CHECK_FALSE(files.at(SERVER + "/b")->deleted);
    CHECK(files.at(SERVER + "/b")->versions.at(0).size == 6);
    CHECK(files.at(SERVER + "/a")->versions.at(0).size == 3);
}

TEST_CASE("NFS OPENATTR does not turn a file into a directory or add children", "[nfs]") {
    StreamBuilder b;
    OpenArgs o;
    o.openType = 1;
    o.claimType = 0;
    o.file = "attr";
    b.add(1, {simple(op::PUTROOTFH), lookup("f"), simple(op::GETFH), write(0, 4)},
          std::vector<ResOp>{ok(op::PUTROOTFH), ok(op::LOOKUP), getfhRes("F"), writeRes(4)}, 0, 4);
    b.add(2, {putfh("F"), simple(op::OPENATTR), ArgOp{op::OPEN, o}, simple(op::GETFH), write(0, 2)},
          std::vector<ResOp>{ok(op::PUTFH), ok(op::OPENATTR), ok(op::OPEN, OpenRes{}), getfhRes("AFH"), writeRes(2)}, 0, 2);
    // without a reply the compound stops at OPENATTR as well
    b.add(3, {putfh("F"), simple(op::OPENATTR), ArgOp{op::OPEN, o}}, std::nullopt);
    const auto files = b.replay();
    REQUIRE(files.count(SERVER + "/f"));
    const NfsFilePtr f = files.at(SERVER + "/f");
    CHECK_FALSE(f->isDirectory);
    REQUIRE(f->versions.size() == 1);
    CHECK(f->versions[0].size == 4);
    CHECK(f->versions[0].content.size() == 1);
    CHECK(childNames(files, SERVER + "/f").empty());
    CHECK(files.size() == 2);   // root and f only
}


TEST_CASE("NFS LINK onto a name that is taken by another object replaces that object", "[nfs]") {
    StreamBuilder b;
    b.add(1, {simple(op::PUTROOTFH), lookup("a"), simple(op::GETFH), write(0, 5)},
          std::vector<ResOp>{ok(op::PUTROOTFH), ok(op::LOOKUP), getfhRes("F"), writeRes(5)}, 0, 5);
    b.add(2, {simple(op::PUTROOTFH), lookup("b"), simple(op::GETFH), write(0, 3)},
          std::vector<ResOp>{ok(op::PUTROOTFH), ok(op::LOOKUP), getfhRes("G"), writeRes(3)}, 10, 3);
    // the REMOVE of b is not in the capture: the successful LINK shows that the name was free again
    const std::vector<ArgOp> linkOps{simple(op::PUTROOTFH), lookup("a"), simple(op::SAVEFH), simple(op::PUTROOTFH), nameOp(op::LINK, "b")};
    b.add(3, linkOps, allOk(linkOps));

    const auto files = b.replay();
    CHECK(childNames(files, SERVER) == (std::vector<std::string>{"a", "b", "b@deleted"}));
    REQUIRE(files.at(SERVER + "/b")->versions.size() == 1);
    CHECK(files.at(SERVER + "/b")->versions.back().size == 5);
    CHECK_FALSE(files.at(SERVER + "/b")->deleted);
    REQUIRE(files.at(SERVER + "/b@deleted")->versions.size() == 1);
    CHECK(files.at(SERVER + "/b@deleted")->versions.back().size == 3);
    CHECK(files.at(SERVER + "/b@deleted")->deleted);
}

namespace {
    // one COMPOUND per 1000 levels: PUTROOTFH or PUTFH(previous), 1000 x LOOKUP "d", GETFH -> prefix<n>
    void addDeepChain(StreamBuilder &b, int &timeMs, std::optional<std::string> startFh, const std::string &prefix, int compounds) {
        for (int c = 0; c < compounds; ++c) {
            std::vector<ArgOp> ops;
            if (c > 0)
                ops.push_back(putfh(prefix + std::to_string(c - 1)));
            else if (startFh)
                ops.push_back(putfh(*startFh));
            else
                ops.push_back(simple(op::PUTROOTFH));
            for (int i = 0; i < 1000; ++i)
                ops.push_back(lookup("d"));
            ops.push_back(simple(op::GETFH));
            std::vector<ResOp> res = allOk(ops);
            res.back() = getfhRes(prefix + std::to_string(c));
            b.add(timeMs++, ops, res);
        }
    }

    // files hold their parent directory: release the chain from the leaves so that the test's own
    // cleanup does not recurse once per level
    void releaseDeepRegistry(ServerFileRegistry &registry) {
        for (auto &entry : registry[SERVER_FILE_TREE_DUMMY])
            std::static_pointer_cast<NfsFile>(entry.second)->setParentDir(nullptr);
    }
}

TEST_CASE("NFS very deep directory chains do not overflow the stack", "[nfs]") {
    StreamBuilder b;
    int timeMs = 1;

    SECTION("emitting a chain of 100000 directories") {
        addDeepChain(b, timeMs, std::nullopt, "r", 100);
        ServerFileRegistry registry = b.replayRegistry();
        CHECK(registry[SERVER_FILE_TREE_DUMMY].size() == 100001);   // the root and one directory per level
        releaseDeepRegistry(registry);
    }
    SECTION("merging two chains of 100000 directories") {
        addDeepChain(b, timeMs, std::nullopt, "r", 100);
        // the same chain again below a filehandle that is not placed yet ...
        addDeepChain(b, timeMs, std::string("X"), "x", 100);
        // ... which turns out to be the root's child "d" (level 1), so the two subtrees are merged
        b.add(timeMs++, {simple(op::PUTROOTFH), lookup("d"), simple(op::GETFH)},
              std::vector<ResOp>{ok(op::PUTROOTFH), ok(op::LOOKUP), getfhRes("X")});
        ServerFileRegistry registry = b.replayRegistry();
        // nothing is lost: levels that are too deep to be merged are kept as a separate subtree
        CHECK(registry[SERVER_FILE_TREE_DUMMY].size() >= 100002);
        CHECK(registry[SERVER_FILE_TREE_DUMMY].size() <= 200002);
        releaseDeepRegistry(registry);
    }
}


TEST_CASE("NFS LOOKUP chain deeper than the tree depth limit is cut", "[nfs]") {
    // one compound with thousands of LOOKUP "a" must neither recurse without bound nor build a path
    // deeper than MAX_TREE_DEPTH (2048); the objects beyond the limit become orphans below unknown-* dirs
    StreamBuilder b;
    std::vector<ArgOp> args{simple(op::PUTROOTFH)};
    for (int i = 0; i < 5000; ++i)
        args.push_back(lookup("a"));
    b.add(1, args, allOk(args));
    const auto files = b.replay();
    size_t maxDepth = 0, orphans = 0;
    for (const auto &e : files) {
        maxDepth = std::max(maxDepth, static_cast<size_t>(std::count(e.first.begin(), e.first.end(), '/')));
        if (e.first.rfind(SERVER + "/unknown-id", 0) == 0 && std::count(e.first.begin(), e.first.end(), '/') == 1)
            ++orphans;
    }
    CHECK(files.size() == 5001);    // root + every looked-up object
    CHECK(maxDepth == 2049);        // 2048 below the root, 2049 below an unknown-* directory
    CHECK(orphans == 5000 / 2048);
}
