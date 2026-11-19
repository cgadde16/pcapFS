#ifndef PCAPFS_VIRTUAL_FILES_NFS_H
#define PCAPFS_VIRTUAL_FILES_NFS_H

#include "serverfile.h"
#include "../filefactory.h"

#include <chrono>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <boost/serialization/map.hpp>
#include <boost/serialization/set.hpp>
#include <boost/serialization/vector.hpp>


namespace pcapfs {

    // sparse content map: file offset -> fragment, non-overlapping; offsets not covered by an entry read as zeros
    using NfsContentMap = std::map<uint64_t, Fragment>;
    using NfsContentPiece = std::pair<uint64_t, Fragment>;   // file offset, fragment (bytes in the underlying TCP file)

    void nfsEraseRange(NfsContentMap &map, uint64_t start, uint64_t end);
    // wire offsets and lengths above this limit are ignored (offset + length must not wrap or exceed it)
    constexpr uint64_t NFS_MAX_RANGE_END = 1ULL << 62;
    inline bool nfsRangeValid(uint64_t offset, uint64_t length) {
        return offset <= NFS_MAX_RANGE_END && length <= NFS_MAX_RANGE_END - offset;
    }
    // marker in NfsVersion::fs.modifyTime / changeTime of a version copied from its predecessor that has no
    // observation of its own yet (1 ns after the epoch; treated as absent when timestamps are picked)
    const TimePoint NFS_FS_TIME_INHERITED = TimePoint(TimePoint::duration(1));
    // overwrites [fileOffset, fileOffset + frag.length) with the fragment (zero-length fragments and
    // fragments with an invalid range are ignored)
    void nfsInsertPiece(NfsContentMap &map, uint64_t fileOffset, const Fragment &frag);
    uint64_t nfsContentEnd(const NfsContentMap &map);
    // entries overlapping [start, end), clipped to it (keys stay absolute file offsets)
    NfsContentMap nfsSliceRange(const NfsContentMap &map, uint64_t start, uint64_t end);
    bool nfsContentEqual(const NfsContentMap &a, const NfsContentMap &b);

    using NfsFetchFn = std::function<void(const Fragment &frag, uint64_t offsetInFragment, size_t length, char *dst)>;
    // copies [start, start + length) of a version of the given size into buf (zero-filled holes), returns bytes written
    size_t nfsReadContent(const NfsContentMap &map, uint64_t size, uint64_t start, size_t length, char *buf,
                          const NfsFetchFn &fetch);


    struct NfsVersion {
        NfsContentMap content;
        uint64_t size = 0;                  // max(highest fragment end, size attrs seen for this version), TRUNCATE sets it exactly
        bool sealed = false;                // the next WRITE starts a new version
        bool hasContentEvents = false;
        // version without content yet, e.g. of a file that was just created
        bool isPlaceholder() const { return !hasContentEvents && content.empty() && !sealed; }
        TimePoint networkStart = TimePoint{};
        TimePoint networkEnd = TimePoint{};
        ServerFileTimestamps fs;            // latest attrs seen while this version was current (TimePoint{} = unknown)
        std::set<std::string> clientIPs;
        bool readOrigin = false;            // version was started by a READ, i.e. the content existed before it was observed
        std::set<TimePoint> accesses;       // network times of READ ops on this version
        // network time -> attrs known at that time, observed while this version was current;
        // capped to the first and the latest observation (nfsRecordFsTimes)
        ServerFileTimestampsMap fsHistory;

        template<class Archive>
        void serialize(Archive &archive, const unsigned int) {
            archive & content;
            archive & size;
            archive & sealed;
            archive & hasContentEvents;
            archive & networkStart;
            archive & networkEnd;
            archive & fs;
            archive & clientIPs;
            archive & readOrigin;
            archive & accesses;
            archive & fsHistory;
        }
    };

    // records attrs observed at a network time; the map keeps only its first and its latest entry
    void nfsRecordFsTimes(ServerFileTimestampsMap &history, const TimePoint &time, const ServerFileTimestamps &ts);


    // a (parent, name) the node had from `since` on; the last entry of NfsFile::placements is the materialized
    // filename / parent directory (parentId = idInIndex of the parent NfsFile, -1 for the server root)
    struct NfsPlacement {
        TimePoint since = TimePoint{};
        int64_t parentId = -1;
        std::string name;

        template<class Archive>
        void serialize(Archive &archive, const unsigned int) {
            archive & since;
            archive & parentId;
            archive & name;
        }
    };


    class NfsFile : public ServerFile {
    public:
        static FilePtr create() { return std::make_shared<NfsFile>(); };

        static std::vector<FilePtr> parse(FilePtr filePtr, Index &idx);
        size_t read(uint64_t startOffset, size_t length, const Index &idx, char *buf) override;

        bool showFile() override;
        void setParentDirId(uint64_t id) { parentDirId = id; };
        // snapshot mode: applies the placement in effect at config.snapshot (filename and parent directory);
        // `byId` maps idInIndex -> file of all nfs files. Does nothing for files without placements.
        void applyPlacementAtSnapshot(const std::map<uint64_t, FilePtr> &byId);
        // snapshot mode: applies the last (materialized) placement; used to break parent cycles
        void applyFinalPlacement(const std::map<uint64_t, FilePtr> &byId);
        void setPlacementMap(const std::map<uint64_t, FilePtr> *byId) { placementMap = byId; }
        bool processFileForDirLayout() { return (!flags.test(pcapfs::flags::IS_METADATA) || config.showMetadata); };

        void touch(const TimePoint &time, const std::string &clientIP = "");
        void applyRead(const std::vector<NfsContentPiece> &pieces, uint64_t endOffset, const TimePoint &time, const std::string &clientIP);
        void applyWrite(const std::vector<NfsContentPiece> &pieces, uint64_t endOffset, const TimePoint &time, const std::string &clientIP);
        void applyHole(uint64_t offset, uint64_t length, const TimePoint &time, const std::string &clientIP);
        // DEALLOCATE: [offset, offset + length) reads as zeros afterwards, the size is unchanged; starts a new version like WRITE
        void applyDeallocate(uint64_t offset, uint64_t length, const TimePoint &time, const std::string &clientIP);
        // ALLOCATE: grows the file to offset + length if that is beyond the current size, otherwise no-op
        void applyAllocate(uint64_t offset, uint64_t length, const TimePoint &time, const std::string &clientIP);
        void applyTruncate(uint64_t size, const TimePoint &time, const std::string &clientIP);
        void applyClose();
        void applyClone(const NfsContentMap &srcContent, uint64_t srcSize, uint64_t srcOffset, uint64_t dstOffset,
                        uint64_t count, const TimePoint &time, const std::string &clientIP);
        void applySizeAttr(uint64_t size);
        void applyFsTimes(const TimePoint &time, const TimePoint *access, const TimePoint *modify, const TimePoint *change,
                          const TimePoint *birth);

        // consecutive versions with structurally identical content are merged
        void mergeIdenticalVersions();
        // consecutive versions with equal size and equal bytes are merged
        void deduplicateVersions(const Index &idx);

        void selectVersion(size_t index);
        // timestamps of the selected version according to config.timestampMode (newest observation, no snip/snapshot)
        void updateTimestamps();

        std::vector<FilePtr> const constructVersionFiles() override;
        bool constructSnapshotFile() override;

        void serialize(boost::archive::text_oarchive &archive) override;
        void deserialize(boost::archive::text_iarchive &archive) override;

        std::vector<NfsVersion> versions;       // chronological
        size_t selectedVersion = 0;
        bool deleted = false;
        TimePoint deletedAt = TimePoint{};
        TimePoint firstSeen = TimePoint{};
        TimePoint lastSeen = TimePoint{};
        ServerFileTimestamps nodeFs;            // latest fs attrs seen for the node, regardless of versions
        ServerFileTimestampsMap nodeFsHistory;  // like NfsVersion::fsHistory, for the node (first and latest observation)
        std::set<TimePoint> observations;       // network times of all compounds that touched the node
        std::chrono::nanoseconds skew{0};       // server clock minus packet time (hybrid mode)
        std::vector<NfsPlacement> placements;   // chronological, see NfsPlacement
        bool createdInCapture = false;          // the name was created inside the capture (CREATE, OPEN that created, LINK)

    private:
        NfsFetchFn fetchFn(const Index &idx) const;
        NfsVersion &startVersion(const TimePoint &time, const std::string &clientIP, const NfsVersion *copyFrom);
        NfsVersion &currentForEvent(bool forWrite, const TimePoint &time, const std::string &clientIP);
        void noteEvent(NfsVersion &v, const TimePoint &time, const std::string &clientIP);

        // network times at which the version was observed (networkStart, READ accesses, networkEnd);
        // without a version: the times the node itself was observed
        std::set<TimePoint> networkCandidates(const NfsVersion *v) const;
        // newest candidate inside the snip interval and, if given, older than *before
        static std::optional<TimePoint> pickNetworkTime(const std::set<TimePoint> &candidates, const TimePoint *before);
        // newest fs observation inside the snip interval (lower bound only if applyLower) whose
        // access/modify/change times are all older than *valuesBefore (if given)
        static const ServerFileTimestamps *pickFsEntry(const ServerFileTimestampsMap &history, bool applyLower,
                                                       const TimePoint *valuesBefore);
        // sets access/modify/change/birth time for the mode: NETWORK -> network times; FS/HYBRID -> fsEntry, then the
        // version's latest attrs, then the node's latest attrs, then the network time (+ skew in HYBRID mode)
        void setTimestamps(const NfsVersion *v, const ServerFileTimestamps *fsEntry, const TimePoint &network,
                           const TimePoint &birthNetwork, const TimePoint *snapshot = nullptr);
        // snapshot mode: finds timestamps older than config.snapshot (and inside the snip interval) for the version or,
        // without a version, for the node; false if there are none (-> file is not displayed)
        bool tryMatchTimestampsToSnapshot(const NfsVersion *v);
        bool matchTimestampsToSnapshot(const NfsVersion *v);
        bool trySetAsMetadataFile(const NfsVersion *v);
        void displayAsMetadataFile();
        // time by which a version or deletion must have happened to be visible at config.snapshot
        TimePoint snapshotNetworkBound() const;
        void applyPlacement(size_t index, const std::map<uint64_t, FilePtr> &byId);
        bool skewed() const { return config.timestampMode != options::TimestampMode::NETWORK; }

        bool donotDisplay = false;
        const std::map<uint64_t, FilePtr> *placementMap = nullptr;     // not serialized, set by the manager

    protected:
        static bool registeredAtFactory;
    };

    typedef std::shared_ptr<NfsFile> NfsFilePtr;
}

#endif //PCAPFS_VIRTUAL_FILES_NFS_H
