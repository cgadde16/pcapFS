#include <catch2/catch.hpp>

#include <chrono>
#include <cstdint>
#include <cstring>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include <boost/archive/text_iarchive.hpp>
#include <boost/archive/text_oarchive.hpp>

#include "../../src/virtualfiles/nfs.h"
#include "nfs-test-utils.h"

using namespace pcapfs;

namespace {
    Fragment frag(uint64_t id, uint64_t start, uint64_t length) {
        Fragment f;
        f.id = id;
        f.start = start;
        f.length = length;
        return f;
    }

    TimePoint tp(int seconds) {
        return TimePoint(std::chrono::seconds(seconds));
    }

    // fake TCP data: byte i of a fragment is (start + offset + i + id) % 251, so the value shows which fragment was read
    const NfsFetchFn fakeFetch = [](const Fragment &f, uint64_t off, size_t len, char *dst) {
        for (size_t i = 0; i < len; ++i)
            dst[i] = static_cast<char>((f.start + off + i + f.id) % 251);
    };

    std::string readAll(const NfsVersion &v) {
        std::string out(v.size, '?');
        const size_t n = nfsReadContent(v.content, v.size, 0, out.size(), out.data(), fakeFetch);
        out.resize(n);
        return out;
    }

    std::vector<NfsContentPiece> one(uint64_t fileOffset, const Fragment &f) {
        return {{fileOffset, f}};
    }
}

TEST_CASE("NFS sparse content map", "[nfs]") {
    NfsContentMap map;

    SECTION("insert into empty and non-overlapping") {
        nfsInsertPiece(map, 0, frag(1, 100, 10));
        nfsInsertPiece(map, 20, frag(1, 200, 5));
        REQUIRE(map.size() == 2);
        REQUIRE(nfsContentEnd(map) == 25);
    }

    SECTION("zero length fragments are ignored") {
        nfsInsertPiece(map, 5, frag(1, 0, 0));
        REQUIRE(map.empty());
        REQUIRE(nfsContentEnd(map) == 0);
    }

    SECTION("overwrite in the middle splits the old entry") {
        nfsInsertPiece(map, 0, frag(1, 1000, 100));
        nfsInsertPiece(map, 40, frag(2, 0, 20));
        REQUIRE(map.size() == 3);
        REQUIRE(map.at(0).start == 1000);
        REQUIRE(map.at(0).length == 40);
        REQUIRE(map.at(40).id == 2);
        REQUIRE(map.at(60).id == 1);
        REQUIRE(map.at(60).start == 1060);
        REQUIRE(map.at(60).length == 40);
    }

    SECTION("overlap of several entries") {
        nfsInsertPiece(map, 0, frag(1, 0, 10));
        nfsInsertPiece(map, 10, frag(1, 100, 10));
        nfsInsertPiece(map, 20, frag(1, 200, 10));
        nfsInsertPiece(map, 5, frag(2, 0, 20));
        REQUIRE(map.size() == 3);
        REQUIRE(map.at(0).length == 5);
        REQUIRE(map.at(5).id == 2);
        REQUIRE(map.at(25).start == 205);
        REQUIRE(map.at(25).length == 5);
        REQUIRE(nfsContentEnd(map) == 30);
    }

    SECTION("exact replacement") {
        nfsInsertPiece(map, 10, frag(1, 0, 10));
        nfsInsertPiece(map, 10, frag(2, 0, 10));
        REQUIRE(map.size() == 1);
        REQUIRE(map.at(10).id == 2);
    }

    SECTION("erase range and slice") {
        nfsInsertPiece(map, 0, frag(1, 0, 100));
        nfsEraseRange(map, 30, 70);
        REQUIRE(map.size() == 2);
        REQUIRE(map.at(70).start == 70);
        const NfsContentMap slice = nfsSliceRange(map, 20, 80);
        REQUIRE(slice.size() == 2);
        REQUIRE(slice.at(20).length == 10);
        REQUIRE(slice.at(70).length == 10);
        REQUIRE(nfsSliceRange(map, 40, 60).empty());
    }

    SECTION("read zero-fills holes and respects the size") {
        nfsInsertPiece(map, 2, frag(0, 10, 3));   // bytes 10 11 12 at file offset 2
        char buf[16];
        const size_t n = nfsReadContent(map, 8, 0, sizeof(buf), buf, fakeFetch);
        REQUIRE(n == 8);
        const char expected[8] = {0, 0, 10, 11, 12, 0, 0, 0};
        REQUIRE(memcmp(buf, expected, 8) == 0);
        REQUIRE(nfsReadContent(map, 8, 8, 4, buf, fakeFetch) == 0);
        REQUIRE(nfsReadContent(map, 8, 3, 2, buf, fakeFetch) == 2);
        REQUIRE(buf[0] == 11);
        REQUIRE(buf[1] == 12);
    }

    SECTION("equality") {
        NfsContentMap other;
        nfsInsertPiece(map, 0, frag(1, 0, 10));
        nfsInsertPiece(other, 0, frag(1, 0, 10));
        REQUIRE(nfsContentEqual(map, other));
        nfsInsertPiece(other, 3, frag(1, 50, 2));
        REQUIRE_FALSE(nfsContentEqual(map, other));
    }
}

TEST_CASE("NFS version rules", "[nfs]") {
    NfsFile f;
    const std::string ip = "10.0.0.2";

    SECTION("write after create stays in one version until close") {
        f.applyTruncate(0, tp(1), ip);              // creation
        f.applyWrite(one(0, frag(1, 0, 10)), 10, tp(2), ip);
        f.applyWrite(one(10, frag(1, 10, 10)), 20, tp(3), ip);
        REQUIRE(f.versions.size() == 1);
        REQUIRE(f.versions[0].size == 20);
        f.applyClose();
        REQUIRE(f.versions[0].sealed);
    }

    SECTION("write after close starts a new version as a copy") {
        f.applyWrite(one(0, frag(1, 0, 10)), 10, tp(1), ip);
        f.applyClose();
        f.applyWrite(one(4, frag(2, 0, 2)), 6, tp(2), ip);
        REQUIRE(f.versions.size() == 2);
        REQUIRE(f.versions[0].content.size() == 1);
        REQUIRE(f.versions[1].content.size() == 3);
        REQUIRE(f.versions[1].size == 10);
        REQUIRE(f.versions[1].networkStart == tp(2));
    }

    SECTION("read inserts into the current version and seals it") {
        f.applyRead(one(0, frag(1, 0, 8)), 8, tp(1), ip);
        REQUIRE(f.versions.size() == 1);
        REQUIRE(f.versions[0].sealed);
        f.applyRead(one(8, frag(1, 8, 8)), 16, tp(2), ip);
        REQUIRE(f.versions.size() == 1);
        REQUIRE(f.versions[0].size == 16);
        f.applyWrite(one(0, frag(2, 0, 4)), 4, tp(3), ip);
        REQUIRE(f.versions.size() == 2);
        REQUIRE(f.versions[1].size == 16);
    }

    SECTION("a zero-length READ or WRITE behind the end does not grow the file") {
        f.applyRead(one(0, frag(1, 0, 10)), 10, tp(1), ip);
        f.applyRead({}, 50, tp(2), ip);             // READ at offset 50: 0 bytes, eof
        REQUIRE(f.versions.size() == 1);
        REQUIRE(f.versions[0].size == 10);
        f.applyWrite({}, 80, tp(3), ip);            // WRITE at offset 80 the server answered with count 0
        REQUIRE(f.versions.back().size == 10);
    }

    SECTION("truncate sequence small / empty / medium") {
        f.applyTruncate(0, tp(1), ip);              // create
        f.applyWrite(one(0, frag(1, 0, 5)), 5, tp(2), ip);
        f.applyClose();
        f.applyTruncate(0, tp(3), ip);              // truncate to empty
        REQUIRE(f.versions.size() == 2);
        REQUIRE(f.versions[1].size == 0);
        REQUIRE(f.versions[1].content.empty());
        f.applyTruncate(0, tp(4), ip);              // O_TRUNC of the already empty file: no-op
        REQUIRE(f.versions.size() == 2);
        f.applyWrite(one(0, frag(1, 100, 30)), 30, tp(5), ip);
        REQUIRE(f.versions.size() == 3);
        REQUIRE(f.versions[2].size == 30);
        REQUIRE(f.versions[0].size == 5);
    }

    SECTION("truncate to a smaller non-zero size cuts the copy") {
        f.applyWrite(one(0, frag(1, 0, 20)), 20, tp(1), ip);
        f.applyClose();
        f.applyTruncate(8, tp(2), ip);
        REQUIRE(f.versions.size() == 2);
        REQUIRE(f.versions[1].size == 8);
        REQUIRE(nfsContentEnd(f.versions[1].content) == 8);
        REQUIRE(f.versions[0].size == 20);
    }

    SECTION("size attribute only grows the current version") {
        f.applyWrite(one(0, frag(1, 0, 10)), 10, tp(1), ip);
        f.applySizeAttr(4);
        REQUIRE(f.versions[0].size == 10);
        f.applySizeAttr(64);
        REQUIRE(f.versions[0].size == 64);
    }

    SECTION("clone into a fresh file reuses the placeholder version") {
        NfsFile src;
        src.applyWrite(one(0, frag(1, 0, 10)), 10, tp(1), ip);
        src.applyWrite(one(10, frag(1, 50, 10)), 20, tp(1), ip);
        f.applyTruncate(0, tp(2), ip);
        f.applyClone(src.versions[0].content, src.versions[0].size, 0, 0, 0, tp(3), ip);
        REQUIRE(f.versions.size() == 1);
        REQUIRE(f.versions[0].size == 20);
        REQUIRE(nfsContentEqual(f.versions[0].content, src.versions[0].content));
        REQUIRE(f.versions[0].sealed);
    }

    SECTION("clone of a range into an existing file creates a version") {
        NfsFile src;
        src.applyWrite(one(0, frag(2, 0, 20)), 20, tp(1), ip);
        f.applyWrite(one(0, frag(1, 0, 10)), 10, tp(1), ip);
        f.applyClose();
        f.applyClone(src.versions[0].content, 20, 5, 2, 4, tp(2), ip);
        REQUIRE(f.versions.size() == 2);
        REQUIRE(f.versions[1].size == 10);
        REQUIRE(readAll(f.versions[1]).substr(2, 4) == std::string("\x07\x08\x09\x0a", 4));   // (5 + i + id 2) % 251
    }

    SECTION("hole extends the size with zeros") {
        f.applyRead(one(0, frag(1, 0, 4)), 4, tp(1), ip);
        f.applyHole(4, 8, tp(2), ip);
        REQUIRE(f.versions[0].size == 12);
        const std::string all = readAll(f.versions[0]);
        REQUIRE(all.size() == 12);
        REQUIRE(all[11] == 0);
    }

    SECTION("identical consecutive versions are merged") {
        f.applyWrite(one(0, frag(1, 0, 10)), 10, tp(1), ip);
        f.applyClose();
        f.applyWrite(one(0, frag(1, 0, 10)), 10, tp(2), ip);   // same fragment again
        REQUIRE(f.versions.size() == 2);
        f.mergeIdenticalVersions();
        REQUIRE(f.versions.size() == 1);
        REQUIRE(f.versions[0].networkEnd == tp(2));
    }

    SECTION("selecting a version fills fragments and size") {
        f.applyWrite(one(0, frag(1, 0, 10)), 10, tp(1), ip);
        f.applyClose();
        f.applyWrite(one(10, frag(1, 10, 5)), 15, tp(2), ip);
        f.selectVersion(0);
        REQUIRE(f.getFilesizeProcessed() == 10);
        REQUIRE(f.fragments.size() == 1);
        f.selectVersion(1);
        REQUIRE(f.getFilesizeProcessed() == 15);
        REQUIRE(f.fragments.size() == 2);
    }
}

TEST_CASE("NFS file serialization round trip", "[nfs]") {
    NfsFile f;
    f.setFilename("medium.bin");
    f.setFiletype("nfs");
    f.setOffsetType("tcp");
    f.setIdInIndex(7);
    f.setParentDirId(3);
    f.setClientIPs({"10.0.0.2"});
    f.deleted = true;
    f.deletedAt = tp(99);
    f.firstSeen = tp(1);
    f.lastSeen = tp(50);
    f.skew = std::chrono::nanoseconds(1500);
    f.applyWrite({{0, frag(1, 0, 10)}, {10, frag(1, 40, 6)}}, 16, tp(2), "10.0.0.2");
    f.applyClose();
    f.applyWrite(one(4, frag(1, 90, 2)), 6, tp(3), "10.0.0.3");
    const TimePoint modTime = tp(20);
    f.applyFsTimes(tp(3), nullptr, &modTime, nullptr, nullptr);
    f.applyRead(one(0, frag(1, 0, 6)), 6, tp(4), "10.0.0.3");
    f.touch(tp(5), "10.0.0.3");
    f.selectVersion(0);

    std::stringstream ss;
    {
        boost::archive::text_oarchive out(ss);
        f.serialize(out);   // File::serialize starts with the filetype, which Index::read consumes itself
    }
    NfsFile g;
    {
        boost::archive::text_iarchive in(ss);
        std::string type;
        in >> type;
        REQUIRE(type == "nfs");
        g.deserialize(in);
    }

    REQUIRE(g.getFilename() == "medium.bin");
    REQUIRE(g.getIdInIndex() == 7);
    REQUIRE(g.getParentDirId() == 3);
    REQUIRE(g.deleted);
    REQUIRE(g.deletedAt == tp(99));
    REQUIRE(g.firstSeen == tp(1));
    REQUIRE(g.lastSeen == tp(50));
    REQUIRE(g.nodeFs.modifyTime == tp(20));
    REQUIRE(g.nodeFsHistory == f.nodeFsHistory);
    REQUIRE(g.nodeFsHistory.size() == 1);
    REQUIRE(g.observations == f.observations);
    REQUIRE(g.observations.count(tp(5)) == 1);
    REQUIRE(g.skew == std::chrono::nanoseconds(1500));
    REQUIRE(g.selectedVersion == 0);
    REQUIRE(g.getFilesizeProcessed() == 16);
    REQUIRE(g.fragments.size() == 2);
    REQUIRE(g.getClientIPs().count("10.0.0.2") == 1);
    REQUIRE(g.versions.size() == f.versions.size());
    for (size_t i = 0; i < f.versions.size(); ++i) {
        REQUIRE(g.versions[i].size == f.versions[i].size);
        REQUIRE(g.versions[i].sealed == f.versions[i].sealed);
        REQUIRE(g.versions[i].hasContentEvents == f.versions[i].hasContentEvents);
        REQUIRE(g.versions[i].networkStart == f.versions[i].networkStart);
        REQUIRE(g.versions[i].networkEnd == f.versions[i].networkEnd);
        REQUIRE(g.versions[i].clientIPs == f.versions[i].clientIPs);
        REQUIRE(g.versions[i].fs == f.versions[i].fs);
        REQUIRE(g.versions[i].readOrigin == f.versions[i].readOrigin);
        REQUIRE(g.versions[i].accesses == f.versions[i].accesses);
        REQUIRE(g.versions[i].fsHistory == f.versions[i].fsHistory);
        REQUIRE(nfsContentEqual(g.versions[i].content, f.versions[i].content));
    }
}

namespace {
    std::shared_ptr<ServerFile> sf(const FilePtr &p) { return std::static_pointer_cast<ServerFile>(p); }

    void fsTimes(NfsFile &f, int at, int access, int modify, int change, int birth = 0) {
        const TimePoint a = tp(access), m = tp(modify), c = tp(change), b = tp(birth);
        f.applyFsTimes(tp(at), access ? &a : nullptr, modify ? &m : nullptr, change ? &c : nullptr, birth ? &b : nullptr);
    }

    // two versions: v0 observed by READs at t=10 and t=12 (file existed before), v1 written at t=20 and read at t=30;
    // server fs times are observed by GETATTR after every op (server clock == network clock); removed at t=40
    NfsFile twoVersionFile() {
        NfsFile f;
        const std::string ip = "10.0.0.2";
        f.setFilename("two.bin");
        f.touch(tp(3), ip);                     // LOOKUP/GETATTR long before the first READ
        fsTimes(f, 3, 3, 2, 2, 1);
        f.applyRead(one(0, frag(1, 0, 10)), 10, tp(10), ip);
        fsTimes(f, 10, 10, 5, 5, 1);
        f.applyRead(one(0, frag(1, 0, 10)), 10, tp(12), ip);
        fsTimes(f, 12, 12, 5, 5, 1);
        f.touch(tp(14), ip);                    // stat without content access
        f.applyWrite(one(0, frag(2, 0, 4)), 4, tp(20), ip);
        fsTimes(f, 20, 12, 20, 20, 1);
        f.applyClose();
        f.applyRead(one(4, frag(1, 4, 6)), 10, tp(30), ip);
        fsTimes(f, 30, 30, 20, 20, 1);
        f.deleted = true;
        f.deletedAt = tp(40);
        f.touch(tp(40), ip);
        f.selectVersion(1);
        REQUIRE(f.versions.size() == 2);
        return f;
    }

    // created and written inside the capture at t=20, no fs attrs ever seen, server clock 7 s ahead
    NfsFile writtenFileWithoutAttrs() {
        NfsFile f;
        f.setFilename("new.bin");
        f.applyTruncate(0, tp(20), "10.0.0.2");
        f.applyWrite(one(0, frag(1, 0, 4)), 4, tp(21), "10.0.0.2");
        f.skew = std::chrono::seconds(7);
        return f;
    }
}

TEST_CASE("NFS fs time history keeps first and latest observation", "[nfs]") {
    NfsFile f;
    fsTimes(f, 1, 10, 10, 10);
    fsTimes(f, 2, 20, 10, 10);
    fsTimes(f, 3, 30, 10, 10);
    REQUIRE(f.nodeFsHistory.size() == 2);
    CHECK(f.nodeFsHistory.begin()->first == tp(1));
    CHECK(f.nodeFsHistory.begin()->second.accessTime == tp(10));
    CHECK(f.nodeFsHistory.rbegin()->first == tp(3));
    CHECK(f.nodeFsHistory.rbegin()->second.accessTime == tp(30));
    CHECK(f.nodeFs.accessTime == tp(30));
}

TEST_CASE("NFS snapshot selects the version that existed at the snapshot time", "[nfs]") {
    nfstest::ConfigGuard guard;
    NfsFile f = twoVersionFile();
    CHECK(f.versions[0].readOrigin);
    CHECK(f.versions[0].accesses == std::set<TimePoint>{tp(10), tp(12)});
    CHECK(f.versions[1].accesses == std::set<TimePoint>{tp(30)});

    SECTION("before a file created in the capture: hidden") {
        NfsFile g = writtenFileWithoutAttrs();
        guard.snapshotAt(tp(15));
        CHECK_FALSE(g.constructSnapshotFile());
        guard.snapshotAt(tp(29));                   // server time 29 = network time 22 (skew 7 s)
        CHECK(g.constructSnapshotFile());
        CHECK(g.getModifyTime() == tp(28));
    }

    SECTION("before the first READ of a pre-existing file: first version") {
        guard.snapshotAt(tp(5));
        REQUIRE(f.constructSnapshotFile());
        CHECK(f.selectedVersion == 0);
        CHECK(f.getFilesizeProcessed() == 10);
        CHECK(f.getAccessTime() == tp(3));      // the only observation before the snapshot
        CHECK(f.getModifyTime() == tp(2));
        guard.snapshotAt(tp(2));                    // nothing observed before -> hidden
        CHECK_FALSE(f.constructSnapshotFile());
    }

    SECTION("between the versions") {
        guard.snapshotAt(tp(15));
        REQUIRE(f.constructSnapshotFile());
        CHECK(f.selectedVersion == 0);
        CHECK(f.fragments.size() == 1);
        CHECK(f.getAccessTime() == tp(12));
        CHECK(f.getModifyTime() == tp(5));
        CHECK(f.getBirthTime() == tp(1));
    }

    SECTION("after the second version") {
        guard.snapshotAt(tp(25));
        REQUIRE(f.constructSnapshotFile());
        CHECK(f.selectedVersion == 1);
        CHECK(f.getFilesizeProcessed() == 10);
        CHECK(f.fragments.size() == 2);
        CHECK(f.getModifyTime() == tp(20));
        // the READ at t=30 is after the snapshot: its access time is not shown
        CHECK(f.getAccessTime() == tp(12));
    }

    SECTION("at or after the deletion: hidden") {
        guard.snapshotAt(tp(40));
        CHECK_FALSE(f.constructSnapshotFile());
        guard.snapshotAt(tp(45));
        CHECK_FALSE(f.constructSnapshotFile());
        guard.snapshotAt(tp(39));
        CHECK(f.constructSnapshotFile());
    }

    SECTION("network mode uses network times") {
        guard.mode(options::TimestampMode::NETWORK);
        guard.snapshotAt(tp(25));
        REQUIRE(f.constructSnapshotFile());
        CHECK(f.selectedVersion == 1);
        CHECK(f.getAccessTime() == tp(20));
        CHECK(f.getModifyTime() == tp(20));
        CHECK(f.getBirthTime() == tp(10));
        guard.snapshotAt(tp(11));
        REQUIRE(f.constructSnapshotFile());
        CHECK(f.selectedVersion == 0);
        CHECK(f.getAccessTime() == tp(10));
    }

    SECTION("fs mode selects by server time and shows attrs older than the snapshot") {
        guard.mode(options::TimestampMode::FS);
        guard.snapshotAt(tp(11));
        REQUIRE(f.constructSnapshotFile());
        CHECK(f.selectedVersion == 0);
        CHECK(f.getAccessTime() == tp(10));      // the observation at t=12 (atime 12) is newer than the snapshot
        guard.snapshotAt(tp(25));
        REQUIRE(f.constructSnapshotFile());
        CHECK(f.selectedVersion == 1);
        CHECK(f.getModifyTime() == tp(20));
    }

    SECTION("hybrid mode applies the server clock skew") {
        NfsFile g = twoVersionFile();
        g.skew = std::chrono::seconds(7);
        guard.snapshotAt(tp(25));       // server time 25 = network time 18 -> second version not yet written
        REQUIRE(g.constructSnapshotFile());
        CHECK(g.selectedVersion == 0);
        guard.snapshotAt(tp(28));
        REQUIRE(g.constructSnapshotFile());
        CHECK(g.selectedVersion == 1);
    }

    SECTION("snip interval without an access of the selected version: metadata file if seen") {
        guard.snapshotAt(tp(15));
        guard.snip(tp(13), std::nullopt);       // only the stat at t=14 is inside the interval
        REQUIRE(f.constructSnapshotFile());
        CHECK(f.flags.test(flags::IS_METADATA));
        CHECK(f.getFilesizeProcessed() == 0);
        guard.snip(tp(13), tp(14));              // nothing observed inside the interval
        NfsFile g = twoVersionFile();
        CHECK_FALSE(g.constructSnapshotFile());
    }

    SECTION("metadata node is hidden before it was seen") {
        NfsFile d;
        d.isDirectory = true;
        d.touch(tp(30), "10.0.0.2");
        fsTimes(d, 30, 30, 30, 30);
        guard.snapshotAt(tp(25));
        CHECK_FALSE(d.constructSnapshotFile());
        guard.snapshotAt(tp(35));
        CHECK(d.constructSnapshotFile());
        CHECK(d.getModifyTime() == tp(30));
    }
}

TEST_CASE("NFS version files per timestamp mode", "[nfs]") {
    nfstest::ConfigGuard guard;
    NfsFile f = twoVersionFile();

    SECTION("hybrid: fs attrs where known") {
        const auto files = f.constructVersionFiles();
        REQUIRE(files.size() == 2);
        CHECK(files[0]->getFilename() == "two.bin@0");
        CHECK(files[1]->getFilename() == "two.bin@1");
        CHECK(sf(files[0])->getAccessTime() == tp(12));
        CHECK(sf(files[0])->getModifyTime() == tp(5));
        CHECK(sf(files[0])->getChangeTime() == tp(5));
        CHECK(sf(files[0])->getBirthTime() == tp(1));
        CHECK(sf(files[1])->getAccessTime() == tp(30));
        CHECK(sf(files[1])->getModifyTime() == tp(20));
        CHECK(sf(files[1])->getBirthTime() == tp(1));
        CHECK(files[0]->getFilesizeProcessed() == 10);
        CHECK(files[1]->getFilesizeProcessed() == 10);
    }

    SECTION("hybrid: network time plus skew when no attrs are known") {
        NfsFile g = writtenFileWithoutAttrs();
        g.constructVersionFiles();
        CHECK(g.getModifyTime() == tp(28));
        CHECK(g.getBirthTime() == tp(27));
    }

    SECTION("fs: network time without skew when no attrs are known") {
        guard.mode(options::TimestampMode::FS);
        NfsFile g = writtenFileWithoutAttrs();
        g.constructVersionFiles();
        CHECK(g.getModifyTime() == tp(21));
        CHECK(g.getBirthTime() == tp(20));
        const auto files = f.constructVersionFiles();
        REQUIRE(files.size() == 2);
        CHECK(sf(files[1])->getAccessTime() == tp(30));
        CHECK(sf(files[1])->getChangeTime() == tp(20));
    }

    SECTION("network: last access of the version, birth = first version") {
        guard.mode(options::TimestampMode::NETWORK);
        const auto files = f.constructVersionFiles();
        REQUIRE(files.size() == 2);
        CHECK(sf(files[0])->getAccessTime() == tp(12));
        CHECK(sf(files[0])->getModifyTime() == tp(12));
        CHECK(sf(files[0])->getBirthTime() == tp(10));
        CHECK(sf(files[1])->getAccessTime() == tp(30));
        CHECK(sf(files[1])->getChangeTime() == tp(30));
        CHECK(sf(files[1])->getBirthTime() == tp(10));
    }

    SECTION("snip excludes versions without an access inside the interval") {
        guard.mode(options::TimestampMode::NETWORK);
        guard.snip(tp(15), tp(35));
        auto files = f.constructVersionFiles();
        REQUIRE(files.size() == 1);
        CHECK(files[0]->getFilename() == "two.bin@1");

        guard.snip(std::nullopt, tp(11));
        files = f.constructVersionFiles();
        REQUIRE(files.size() == 1);
        CHECK(files[0]->getFilename() == "two.bin@0");
        CHECK(sf(files[0])->getAccessTime() == tp(10));     // the READ at t=12 is outside the interval

        guard.snip(tp(50), std::nullopt);
        files = f.constructVersionFiles();
        CHECK(files.empty());
        CHECK_FALSE(f.showFile());
    }

    SECTION("snip on a single-version file") {
        NfsFile g = writtenFileWithoutAttrs();
        guard.snip(std::nullopt, tp(15));
        CHECK(g.constructVersionFiles().empty());
        CHECK_FALSE(g.showFile());
        NfsFile h = writtenFileWithoutAttrs();
        guard.snip(std::nullopt, tp(25));
        CHECK(h.constructVersionFiles().empty());
        CHECK(h.showFile());
    }
}

TEST_CASE("NFS deduplicateVersions does not walk the zero tail of huge files", "[nfs]") {
    NfsFile f;
    f.setOffsetType("tcp");
    const std::string ip = "10.0.0.2";
    const uint64_t huge = 1ULL << 40;
    f.applyWrite(one(0, frag(1, 0, 10)), huge, tp(1), ip);
    f.applyClose();
    f.applyWrite(one(0, frag(1, 0, 10)), huge, tp(2), ip);
    REQUIRE(f.versions.size() == 2);
    REQUIRE(f.versions[0].size == huge);
    REQUIRE(f.versions[1].size == huge);
    Index idx;
    const auto backing = std::make_shared<NfsFile>();   // stands in for the TCP file the fragments refer to
    backing->setFiletype("tcp");
    backing->setIdInIndex(1);
    idx.insert(backing);
    f.deduplicateVersions(idx);     // must return quickly
    CHECK(f.versions.size() == 1);
}

TEST_CASE("NFS deduplicateVersions only compares the ranges that carry content", "[nfs]") {
    // a small WRITE at a huge offset: the hole in front of it must not be walked chunk by chunk
    const std::string ip = "10.0.0.2";
    const uint64_t far = 1ULL << 60;
    Index idx;
    const auto backing = std::make_shared<NfsFile>();   // stands in for the TCP file the fragments refer to
    backing->setFiletype("tcp");
    backing->setIdInIndex(1);
    idx.insert(backing);

    SECTION("same content at the far offset is one version") {
        NfsFile f;
        f.setOffsetType("tcp");
        f.applyWrite(one(far, frag(1, 0, 10)), far + 10, tp(1), ip);
        f.applyClose();
        f.applyWrite(one(far, frag(1, 0, 10)), far + 10, tp(2), ip);
        REQUIRE(f.versions.size() == 2);
        f.deduplicateVersions(idx);
        CHECK(f.versions.size() == 1);
    }

    SECTION("pieces at different offsets with overlapping and nested ranges") {
        NfsFile f;
        f.setOffsetType("tcp");
        f.applyWrite(one(0, frag(1, 0, 10)), far + 10, tp(1), ip);
        f.applyWrite(one(far, frag(1, 0, 10)), far + 10, tp(1), ip);
        f.applyClose();
        f.applyWrite(one(4, frag(1, 4, 2)), far + 10, tp(2), ip);
        f.applyWrite(one(far - 5, frag(1, 20, 10)), far + 10, tp(2), ip);
        REQUIRE(f.versions.size() == 2);
        f.deduplicateVersions(idx);     // must return quickly
        CHECK(f.versions.size() == 1);
    }
}

TEST_CASE("NFS snip upper bound is exclusive for the snapshot metadata fallback", "[nfs]") {
    nfstest::ConfigGuard guard;
    guard.mode(options::TimestampMode::NETWORK);
    guard.snapshotAt(tp(100));
    guard.snip(std::nullopt, tp(20));
    NfsFile f;
    f.setFilename("edge.bin");
    f.touch(tp(5), "10.0.0.2");
    f.applyWrite(one(0, frag(1, 0, 4)), 4, tp(20), "10.0.0.2");     // networkStart == snip.second
    REQUIRE(f.constructSnapshotFile());
    CHECK(f.flags.test(pcapfs::flags::IS_METADATA));
    CHECK(f.getFilesizeProcessed() == 0);
    CHECK(f.getModifyTime() == tp(5));

    // one nanosecond earlier the version still counts as accessed inside the interval
    NfsFile g;
    g.setFilename("inside.bin");
    g.touch(tp(5), "10.0.0.2");
    g.applyWrite(one(0, frag(1, 0, 4)), 4, tp(20) - std::chrono::nanoseconds(1), "10.0.0.2");
    REQUIRE(g.constructSnapshotFile());
    CHECK_FALSE(g.flags.test(pcapfs::flags::IS_METADATA));
    CHECK(g.getFilesizeProcessed() == 4);
}

TEST_CASE("NFS snapshot fall-backs for missing fs times never lie after the snapshot", "[nfs]") {
    nfstest::ConfigGuard guard;
    guard.mode(options::TimestampMode::FS);
    guard.snapshotAt(tp(20));
    NfsFile f;
    f.setFilename("late.bin");
    // pre-existing file, first READ at t=30; the server reports mtime/ctime 5 but never a birth or atime
    f.applyRead(one(0, frag(1, 0, 10)), 10, tp(30), "10.0.0.2");
    fsTimes(f, 30, 0, 5, 5);
    REQUIRE(f.constructSnapshotFile());
    CHECK(f.getBirthTime() == tp(5));
    CHECK(f.getAccessTime() <= tp(20));
    CHECK(f.getModifyTime() == tp(5));
    CHECK(f.getChangeTime() == tp(5));
}

TEST_CASE("NFS ignores offset and length pairs that wrap or exceed 2^62", "[nfs]") {
    const uint64_t big = 0xFFFFFFFFFFFFFF00ULL;
    CHECK(nfsRangeValid(0, 1ULL << 62));
    CHECK_FALSE(nfsRangeValid(0, (1ULL << 62) + 1));
    CHECK_FALSE(nfsRangeValid(big, 4096));
    CHECK_FALSE(nfsRangeValid(1ULL << 62, 1));

    NfsContentMap map;
    nfsInsertPiece(map, 0, frag(1, 0, 10));
    nfsInsertPiece(map, big, frag(1, 0, 4096));
    CHECK(map.size() == 1);
    CHECK(nfsContentEnd(map) == 10);

    NfsFile f;
    const std::string ip = "10.0.0.2";
    f.applyWrite(one(0, frag(1, 0, 10)), 10, tp(1), ip);
    f.applyHole(big, 4096, tp(2), ip);
    f.applyAllocate(big, 4096, tp(3), ip);
    f.applyDeallocate(big, 4096, tp(4), ip);
    f.applyHole(0, 1ULL << 63, tp(5), ip);
    REQUIRE(f.versions.size() == 1);
    CHECK(f.versions[0].size == 10);
    CHECK(f.versions[0].content.size() == 1);

    NfsFile dst;
    NfsContentMap src;
    src.emplace(0, frag(1, 0, 10));
    dst.applyClone(src, 10, 0, big, 10, tp(6), ip);
    REQUIRE(dst.versions.size() == 1);
    CHECK(dst.versions[0].size == 0);
    CHECK(dst.versions[0].content.empty());
    dst.applyClone(src, 10, big, 0, 10, tp(7), ip);     // source offset beyond the source size
    CHECK(dst.versions.back().content.empty());
}


TEST_CASE("NFS ignores truncate and size attributes above 2^62", "[nfs]") {
    const std::string ip = "10.0.0.2";
    for (const uint64_t huge : {0xFFFFFFFFFFFFFFFFULL, (1ULL << 62) + 1}) {
        NfsFile f;
        f.applyWrite(one(0, frag(1, 0, 10)), 10, tp(1), ip);
        f.applyTruncate(huge, tp(2), ip);
        f.applySizeAttr(huge);
        REQUIRE(f.versions.size() == 1);
        CHECK(f.versions[0].size == 10);

        NfsFile g;      // creation by a truncate
        g.applyTruncate(huge, tp(1), ip);
        CHECK(g.versions.empty());
        g.applySizeAttr(huge);
        CHECK(g.versions.empty());
    }
    NfsFile h;
    h.applyWrite(one(0, frag(1, 0, 10)), 10, tp(1), ip);
    h.applySizeAttr(1ULL << 62);        // the limit itself is still accepted
    CHECK(h.versions[0].size == (1ULL << 62));
}

TEST_CASE("NFS version without own attributes does not show the previous mtime", "[nfs]") {
    nfstest::ConfigGuard guard;
    const std::string ip = "10.0.0.2";
    NfsFile f;
    f.setFilename("v.bin");
    f.applyWrite(one(0, frag(1, 0, 10)), 10, tp(10), ip);
    fsTimes(f, 11, 11, 5, 6, 1);            // GETATTR while version 0 is current: atime 11, mtime 5, ctime 6, crtime 1
    f.applyClose();
    f.applyWrite(one(0, frag(2, 0, 4)), 10, tp(20), ip);    // version 1, no GETATTR afterwards
    f.applyClose();
    REQUIRE(f.versions.size() == 2);
    f.skew = std::chrono::seconds(7);

    SECTION("hybrid: network time plus skew, birth and access inherited") {
        const auto files = f.constructVersionFiles();
        REQUIRE(files.size() == 2);
        CHECK(sf(files[0])->getModifyTime() == tp(5));
        CHECK(sf(files[0])->getChangeTime() == tp(6));
        CHECK(sf(files[1])->getModifyTime() == tp(27));
        CHECK(sf(files[1])->getChangeTime() == tp(27));
        CHECK(sf(files[1])->getBirthTime() == tp(1));
        CHECK(sf(files[1])->getAccessTime() == tp(11));
    }

    SECTION("fs: network time without skew") {
        guard.mode(options::TimestampMode::FS);
        const auto files = f.constructVersionFiles();
        REQUIRE(files.size() == 2);
        CHECK(sf(files[0])->getModifyTime() == tp(5));
        CHECK(sf(files[1])->getModifyTime() == tp(20));
        CHECK(sf(files[1])->getChangeTime() == tp(20));
    }

    SECTION("its own observation takes over") {
        fsTimes(f, 21, 21, 20, 20, 1);
        const auto files = f.constructVersionFiles();
        REQUIRE(files.size() == 2);
        CHECK(sf(files[1])->getModifyTime() == tp(20));
        CHECK(sf(files[0])->getModifyTime() == tp(5));
    }

    SECTION("an observation without time_modify keeps the version on network time") {
        fsTimes(f, 21, 21, 0, 0, 0);        // atime only
        const auto files = f.constructVersionFiles();
        REQUIRE(files.size() == 2);
        CHECK(sf(files[1])->getAccessTime() == tp(21));
        CHECK(sf(files[1])->getModifyTime() == tp(27));
    }

    SECTION("serialization keeps the network time fallback of the version") {
        std::stringstream ss;
        {
            boost::archive::text_oarchive oa(ss);
            f.setFiletype("nfs");
            f.serialize(oa);
        }
        NfsFile g;
        {
            boost::archive::text_iarchive ia(ss);
            std::string type;
            ia >> type;
            g.deserialize(ia);
        }
        const auto files = g.constructVersionFiles();
        REQUIRE(files.size() == 2);
        CHECK(sf(files[1])->getModifyTime() == tp(27));
    }
}


TEST_CASE("NFS placements and createdInCapture survive the serialization round trip", "[nfs]") {
    NfsFile f;
    f.setFilename("b");
    f.setFiletype("nfs");
    f.setOffsetType("tcp");
    f.setIdInIndex(7);
    f.createdInCapture = true;
    f.placements = {{tp(1), 3, "a"}, {tp(9), 4, "b"}};

    std::stringstream ss;
    {
        boost::archive::text_oarchive out(ss);
        f.serialize(out);
    }
    NfsFile g;
    {
        boost::archive::text_iarchive in(ss);
        std::string type;
        in >> type;
        g.deserialize(in);
    }
    REQUIRE(g.createdInCapture);
    REQUIRE(g.placements.size() == 2);
    CHECK(g.placements[0].since == tp(1));
    CHECK(g.placements[0].parentId == 3);
    CHECK(g.placements[0].name == "a");
    CHECK(g.placements[1].since == tp(9));
    CHECK(g.placements[1].parentId == 4);
    CHECK(g.placements[1].name == "b");

    // copies (hard link clones, version files) carry the placements
    const NfsFile copy(f);
    CHECK(copy.placements.size() == 2);
    CHECK(copy.createdInCapture);
}

TEST_CASE("NFS snapshot places a renamed file where it was at the snapshot time", "[nfs]") {
    nfstest::ConfigGuard guard;
    guard.mode(options::TimestampMode::NETWORK);

    auto dir = [](uint64_t id, const std::string &name) {
        auto d = std::make_shared<NfsFile>();
        d->setIdInIndex(id);
        d->setFilename(name);
        d->isDirectory = true;
        return d;
    };
    const auto d1 = dir(1, "d1");
    const auto d2 = dir(2, "d2");
    const std::map<uint64_t, FilePtr> byId{{1, d1}, {2, d2}};

    NfsFile f = twoVersionFile();       // exists (read origin), versions at 10..30
    f.setFilename("new");
    f.setParentDir(d2);
    f.setParentDirId(2);
    f.placements = {{tp(3), 1, "old"}, {tp(20), 2, "new"}};

    SECTION("before the rename") {
        guard.snapshotAt(tp(15));
        f.setPlacementMap(&byId);
        REQUIRE(f.constructSnapshotFile());
        CHECK(f.getFilename() == "old");
        CHECK(f.getParentDir() == d1);
        CHECK(f.getParentDirId() == 1);
    }
    SECTION("after the rename") {
        guard.snapshotAt(tp(25));
        f.setPlacementMap(&byId);
        REQUIRE(f.constructSnapshotFile());
        CHECK(f.getFilename() == "new");
        CHECK(f.getParentDir() == d2);
    }
    SECTION("before the first placement the first one applies (file existed before the capture)") {
        guard.snapshotAt(tp(2));
        f.setPlacementMap(&byId);
        f.constructSnapshotFile();
        CHECK(f.getFilename() == "old");
        CHECK(f.getParentDirId() == 1);
    }
    SECTION("directories are placed like files") {
        NfsFile d;
        d.isDirectory = true;
        d.firstSeen = tp(1);
        d.lastSeen = tp(30);
        d.observations = {tp(1), tp(30)};
        d.setFilename("dirnew");
        d.setParentDirId(2);
        d.placements = {{tp(1), 1, "dirold"}, {tp(20), 2, "dirnew"}};
        d.setPlacementMap(&byId);
        guard.snapshotAt(tp(10));
        REQUIRE(d.constructSnapshotFile());
        CHECK(d.getFilename() == "dirold");
        CHECK(d.getParentDirId() == 1);
        guard.snapshotAt(tp(21));
        REQUIRE(d.constructSnapshotFile());
        CHECK(d.getFilename() == "dirnew");
        CHECK(d.getParentDirId() == 2);
    }
    SECTION("hybrid mode compares the placement time on the server clock") {
        guard.mode(options::TimestampMode::HYBRID);
        f.skew = std::chrono::seconds(7);
        f.setPlacementMap(&byId);
        guard.snapshotAt(tp(25));               // network time 18: before the rename at 20
        f.constructSnapshotFile();
        CHECK(f.getFilename() == "old");
        guard.snapshotAt(tp(28));               // network time 21
        f.constructSnapshotFile();
        CHECK(f.getFilename() == "new");
    }
    SECTION("fs mode compares the placement time on the server clock") {
        guard.mode(options::TimestampMode::FS);
        f.skew = std::chrono::seconds(7);
        f.setPlacementMap(&byId);
        guard.snapshotAt(tp(25));               // network time 18: before the rename at 20
        f.constructSnapshotFile();
        CHECK(f.getFilename() == "old");
        guard.snapshotAt(tp(28));               // network time 21
        f.constructSnapshotFile();
        CHECK(f.getFilename() == "new");
    }
}

TEST_CASE("NFS name created in the capture does not exist before its first placement", "[nfs]") {
    nfstest::ConfigGuard guard;
    guard.mode(options::TimestampMode::NETWORK);
    const std::map<uint64_t, FilePtr> byId;

    // content (and observations) are older than the name, as for a hard link
    NfsFile f = twoVersionFile();
    f.createdInCapture = true;
    f.placements = {{tp(20), 1, "link"}};
    f.setPlacementMap(&byId);

    SECTION("snapshot before the name was created") {
        guard.snapshotAt(tp(15));
        CHECK_FALSE(f.constructSnapshotFile());
        guard.snapshotAt(tp(21));
        CHECK(f.constructSnapshotFile());
    }
    SECTION("without createdInCapture the name is assumed to have existed") {
        f.createdInCapture = false;
        guard.snapshotAt(tp(15));
        CHECK(f.constructSnapshotFile());
    }
    SECTION("snip ending before the name was created: not displayed at all") {
        guard.snip(std::nullopt, tp(20));
        CHECK(f.constructVersionFiles().empty());
        CHECK_FALSE(f.showFile());
    }
    SECTION("snip ending after the name was created") {
        guard.snip(std::nullopt, tp(21));
        f.constructVersionFiles();
        CHECK(f.showFile());
    }
}
