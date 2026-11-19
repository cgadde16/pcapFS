#include "nfs.h"
#include "nfs/nfs_manager.h"
#include "../index.h"
#include "../logging.h"

#include <algorithm>
#include <cstring>
#include <limits>
#include <optional>


void pcapfs::nfsEraseRange(NfsContentMap &map, uint64_t start, uint64_t end) {
    if (start >= end || map.empty())
        return;
    auto it = map.upper_bound(start);
    if (it != map.begin())
        --it;
    while (it != map.end() && it->first < end) {
        const uint64_t entryStart = it->first;
        const Fragment frag = it->second;
        const uint64_t entryEnd = entryStart + frag.length;
        if (entryEnd <= start) {
            ++it;
            continue;
        }
        it = map.erase(it);
        if (entryStart < start) {
            Fragment left = frag;
            left.length = start - entryStart;
            map.emplace(entryStart, left);
        }
        if (entryEnd > end) {
            Fragment right = frag;
            right.start = frag.start + (end - entryStart);
            right.length = entryEnd - end;
            map.emplace(end, right);
            break;
        }
    }
}


void pcapfs::nfsInsertPiece(NfsContentMap &map, uint64_t fileOffset, const Fragment &frag) {
    if (frag.length == 0 || !nfsRangeValid(fileOffset, frag.length))
        return;
    nfsEraseRange(map, fileOffset, fileOffset + frag.length);
    map[fileOffset] = frag;
}


uint64_t pcapfs::nfsContentEnd(const NfsContentMap &map) {
    if (map.empty())
        return 0;
    const auto last = map.rbegin();
    return last->first + last->second.length;
}


pcapfs::NfsContentMap pcapfs::nfsSliceRange(const NfsContentMap &map, uint64_t start, uint64_t end) {
    NfsContentMap result;
    if (start >= end || map.empty())
        return result;
    auto it = map.upper_bound(start);
    if (it != map.begin())
        --it;
    for (; it != map.end() && it->first < end; ++it) {
        const uint64_t entryStart = it->first;
        const uint64_t entryEnd = entryStart + it->second.length;
        if (entryEnd <= start)
            continue;
        const uint64_t from = std::max(entryStart, start);
        const uint64_t to = std::min(entryEnd, end);
        Fragment frag = it->second;
        frag.start += from - entryStart;
        frag.length = to - from;
        result.emplace(from, frag);
    }
    return result;
}


bool pcapfs::nfsContentEqual(const NfsContentMap &a, const NfsContentMap &b) {
    if (a.size() != b.size())
        return false;
    for (auto ia = a.begin(), ib = b.begin(); ia != a.end(); ++ia, ++ib) {
        if (ia->first != ib->first || ia->second.id != ib->second.id || ia->second.start != ib->second.start ||
            ia->second.length != ib->second.length)
            return false;
    }
    return true;
}


size_t pcapfs::nfsReadContent(const NfsContentMap &map, uint64_t size, uint64_t start, size_t length, char *buf,
                              const NfsFetchFn &fetch) {
    if (start >= size || length == 0)
        return 0;
    const size_t toRead = static_cast<size_t>(std::min<uint64_t>(length, size - start));
    memset(buf, 0, toRead);
    const uint64_t end = start + toRead;
    auto it = map.upper_bound(start);
    if (it != map.begin())
        --it;
    for (; it != map.end() && it->first < end; ++it) {
        const uint64_t entryStart = it->first;
        const uint64_t entryEnd = entryStart + it->second.length;
        if (entryEnd <= start)
            continue;
        const uint64_t from = std::max(entryStart, start);
        const uint64_t to = std::min(entryEnd, end);
        fetch(it->second, from - entryStart, static_cast<size_t>(to - from), buf + (from - start));
    }
    return toRead;
}


void pcapfs::nfsRecordFsTimes(ServerFileTimestampsMap &history, const TimePoint &time, const ServerFileTimestamps &ts) {
    history[time] = ts;
    while (history.size() > 2)
        history.erase(std::next(history.begin()));
}


bool pcapfs::NfsFile::showFile() {
    if (donotDisplay ||
        (flags.test(pcapfs::flags::IS_METADATA) && !config.showMetadata) ||
        (!config.showAll && flags.test(pcapfs::flags::PARSED)))
        return false;
    if (config.timestampMode == pcapfs::options::TimestampMode::NETWORK &&
        ((options::LOWER_SNIP_SPECIFIED && accessTime < config.snip.first) ||
         (options::UPPER_SNIP_SPECIFIED && accessTime >= config.snip.second)))
        return false;
    return true;
}


std::vector<pcapfs::FilePtr> pcapfs::NfsFile::parse(FilePtr filePtr, Index &idx) {
    (void)filePtr;
    (void)idx;
    return std::vector<pcapfs::FilePtr>(0);
}


size_t pcapfs::NfsFile::read(uint64_t startOffset, size_t length, const Index &idx, char *buf) {
    if (versions.empty() || selectedVersion >= versions.size() || flags.test(pcapfs::flags::IS_METADATA))
        return 0;
    const NfsVersion &v = versions.at(selectedVersion);
    return nfsReadContent(v.content, v.size, startOffset, length, buf, fetchFn(idx));
}


pcapfs::NfsFetchFn pcapfs::NfsFile::fetchFn(const Index &idx) const {
    return [this, &idx](const Fragment &frag, uint64_t offsetInFragment, size_t len, char *dst) {
        FilePtr filePtr = idx.get({offsetType, frag.id});
        if (filePtr)
            filePtr->read(frag.start + offsetInFragment, len, idx, dst);
    };
}


void pcapfs::NfsFile::touch(const TimePoint &time, const std::string &clientIP) {
    if (time != TimePoint{})
        observations.insert(time);
    if (firstSeen == TimePoint{} || time < firstSeen)
        firstSeen = time;
    if (time > lastSeen)
        lastSeen = time;
    if (!clientIP.empty())
        clientIPs.insert(clientIP);
}


void pcapfs::NfsFile::noteEvent(NfsVersion &v, const TimePoint &time, const std::string &clientIP) {
    if (v.networkStart == TimePoint{} || time < v.networkStart)
        v.networkStart = time;
    if (time > v.networkEnd)
        v.networkEnd = time;
    if (!clientIP.empty())
        v.clientIPs.insert(clientIP);
    touch(time, clientIP);
}


pcapfs::NfsVersion &pcapfs::NfsFile::startVersion(const TimePoint &time, const std::string &clientIP, const NfsVersion *copyFrom) {
    NfsVersion v;
    if (copyFrom) {
        v.content = copyFrom->content;
        v.size = copyFrom->size;
        v.fs = copyFrom->fs;
        // the new version has not been observed yet: the modify/change times of the previous version must not
        // be shown for it (setTimestamps treats the marker as absent); birth/access times stay inherited
        v.fs.modifyTime = NFS_FS_TIME_INHERITED;
        v.fs.changeTime = NFS_FS_TIME_INHERITED;
    }
    v.networkStart = v.networkEnd = time;
    versions.push_back(std::move(v));
    noteEvent(versions.back(), time, clientIP);
    return versions.back();
}


pcapfs::NfsVersion &pcapfs::NfsFile::currentForEvent(bool forWrite, const TimePoint &time, const std::string &clientIP) {
    if (versions.empty())
        return startVersion(time, clientIP, nullptr);
    if (forWrite && versions.back().sealed) {
        const NfsVersion previous = versions.back();
        return startVersion(time, clientIP, &previous);
    }
    noteEvent(versions.back(), time, clientIP);
    return versions.back();
}


void pcapfs::NfsFile::applyWrite(const std::vector<NfsContentPiece> &pieces, uint64_t endOffset, const TimePoint &time,
                                 const std::string &clientIP) {
    NfsVersion &v = currentForEvent(true, time, clientIP);
    for (const auto &piece : pieces)
        nfsInsertPiece(v.content, piece.first, piece.second);
    // a WRITE answered with count 0 says nothing about the size
    v.size = std::max({v.size, pieces.empty() ? uint64_t{0} : endOffset, nfsContentEnd(v.content)});
    v.hasContentEvents = true;
}


void pcapfs::NfsFile::applyRead(const std::vector<NfsContentPiece> &pieces, uint64_t endOffset, const TimePoint &time,
                                const std::string &clientIP) {
    const bool fresh = versions.empty();
    NfsVersion &v = currentForEvent(false, time, clientIP);
    if (fresh)
        v.readOrigin = true;
    v.accesses.insert(time);
    for (const auto &piece : pieces)
        nfsInsertPiece(v.content, piece.first, piece.second);
    // a READ at or behind the end transfers no bytes and says nothing about the size
    v.size = std::max({v.size, pieces.empty() ? uint64_t{0} : endOffset, nfsContentEnd(v.content)});
    v.hasContentEvents = true;
    v.sealed = true;
}


void pcapfs::NfsFile::applyHole(uint64_t offset, uint64_t length, const TimePoint &time, const std::string &clientIP) {
    if (!nfsRangeValid(offset, length))
        return;
    NfsVersion &v = currentForEvent(false, time, clientIP);
    nfsEraseRange(v.content, offset, offset + length);
    v.size = std::max(v.size, offset + length);
    v.hasContentEvents = true;
}


void pcapfs::NfsFile::applyDeallocate(uint64_t offset, uint64_t length, const TimePoint &time, const std::string &clientIP) {
    if (!nfsRangeValid(offset, length))
        return;
    NfsVersion &v = currentForEvent(true, time, clientIP);
    nfsEraseRange(v.content, offset, offset + length);
    v.hasContentEvents = true;
}


void pcapfs::NfsFile::applyAllocate(uint64_t offset, uint64_t length, const TimePoint &time, const std::string &clientIP) {
    if (!nfsRangeValid(offset, length))
        return;
    const uint64_t end = offset + length;
    if (!versions.empty() && end <= versions.back().size) {
        noteEvent(versions.back(), time, clientIP);
        return;
    }
    NfsVersion &v = currentForEvent(true, time, clientIP);
    v.size = std::max(v.size, end);
    v.hasContentEvents = true;
}


void pcapfs::NfsFile::applyTruncate(uint64_t size, const TimePoint &time, const std::string &clientIP) {
    if (!nfsRangeValid(0, size))
        return;
    if (versions.empty()) {
        // creation, not a truncation
        NfsVersion &v = startVersion(time, clientIP, nullptr);
        v.size = size;
        return;
    }
    NfsVersion &cur = versions.back();
    if (cur.size == size) {
        noteEvent(cur, time, clientIP);
        return;
    }
    if (cur.isPlaceholder()) {
        noteEvent(cur, time, clientIP);
        cur.size = size;
        return;
    }
    const NfsVersion previous = cur;
    NfsVersion &v = startVersion(time, clientIP, &previous);
    nfsEraseRange(v.content, size, std::numeric_limits<uint64_t>::max());
    v.size = size;
    v.sealed = true;
    v.hasContentEvents = true;
}


void pcapfs::NfsFile::applyClose() {
    if (!versions.empty())
        versions.back().sealed = true;
}


void pcapfs::NfsFile::applyClone(const NfsContentMap &srcContent, uint64_t srcSize, uint64_t srcOffset,
                                 uint64_t dstOffset, uint64_t count, const TimePoint &time, const std::string &clientIP) {
    uint64_t length = count;
    if (srcOffset >= srcSize)
        length = 0;
    else if (length == 0 || length > srcSize - srcOffset)
        length = srcSize - srcOffset;
    if (!nfsRangeValid(dstOffset, length))
        length = 0;     // ignore the copy, the version is still started

    NfsVersion *v;
    if (!versions.empty() && versions.back().isPlaceholder()) {
        v = &versions.back();
        noteEvent(*v, time, clientIP);
    } else if (versions.empty()) {
        v = &startVersion(time, clientIP, nullptr);
    } else {
        const NfsVersion previous = versions.back();
        v = &startVersion(time, clientIP, &previous);
    }
    if (length > 0) {
        nfsEraseRange(v->content, dstOffset, dstOffset + length);
        const NfsContentMap slice = nfsSliceRange(srcContent, srcOffset, srcOffset + length);
        for (const auto &entry : slice) {
            nfsInsertPiece(v->content, dstOffset + (entry.first - srcOffset), entry.second);
        }
        v->size = std::max(v->size, dstOffset + length);
    }
    v->hasContentEvents = true;
    v->sealed = true;
}


void pcapfs::NfsFile::applySizeAttr(uint64_t size) {
    if (!nfsRangeValid(0, size))
        return;
    if (!versions.empty())
        versions.back().size = std::max(versions.back().size, size);
}


void pcapfs::NfsFile::applyFsTimes(const TimePoint &time, const TimePoint *access, const TimePoint *modify,
                                   const TimePoint *change, const TimePoint *birth) {
    auto update = [&](ServerFileTimestamps &ts) {
        if (access)
            ts.accessTime = *access;
        if (modify)
            ts.modifyTime = *modify;
        if (change)
            ts.changeTime = *change;
        if (birth)
            ts.birthTime = *birth;
    };
    update(nodeFs);
    nfsRecordFsTimes(nodeFsHistory, time, nodeFs);
    if (!versions.empty()) {
        update(versions.back().fs);
        nfsRecordFsTimes(versions.back().fsHistory, time, versions.back().fs);
    }
}


namespace {
    // merges version b into its predecessor a
    void mergeVersionInto(pcapfs::NfsVersion &a, const pcapfs::NfsVersion &b) {
        a.clientIPs.insert(b.clientIPs.begin(), b.clientIPs.end());
        a.networkEnd = std::max(a.networkEnd, b.networkEnd);
        a.fs = b.fs;
        a.sealed = b.sealed;
        a.hasContentEvents = a.hasContentEvents || b.hasContentEvents;
        a.accesses.insert(b.accesses.begin(), b.accesses.end());
        a.accesses.insert(b.networkStart);
        for (const auto &entry : b.fsHistory)
            pcapfs::nfsRecordFsTimes(a.fsHistory, entry.first, entry.second);
    }
}


void pcapfs::NfsFile::mergeIdenticalVersions() {
    for (size_t i = versions.size(); i > 1; --i) {
        NfsVersion &a = versions[i - 2];
        NfsVersion &b = versions[i - 1];
        if (a.size != b.size || !nfsContentEqual(a.content, b.content))
            continue;
        mergeVersionInto(a, b);
        versions.erase(versions.begin() + (i - 1));
    }
}


void pcapfs::NfsFile::deduplicateVersions(const Index &idx) {
    constexpr size_t CHUNK = 1 << 20;
    const NfsFetchFn fetch = fetchFn(idx);
    std::vector<char> bufA(CHUNK), bufB(CHUNK);
    for (size_t i = versions.size(); i > 1; --i) {
        NfsVersion &a = versions[i - 2];
        NfsVersion &b = versions[i - 1];
        if (a.size != b.size)
            continue;
        bool same = true;
        // compare only the ranges that carry content in one of the two versions; holes read as zeros in both
        std::vector<std::pair<uint64_t, uint64_t>> ranges;
        ranges.reserve(a.content.size() + b.content.size());
        for (const NfsContentMap *map : {&a.content, &b.content})
            for (const auto &entry : *map)
                ranges.emplace_back(entry.first, entry.first + entry.second.length);
        std::sort(ranges.begin(), ranges.end());
        uint64_t done = 0;      // everything below this offset has been compared
        for (auto range = ranges.begin(); range != ranges.end() && same; ++range) {
            const uint64_t end = std::min(range->second, a.size);
            for (uint64_t pos = std::max(range->first, done); pos < end && same; pos += CHUNK) {
                const size_t len = static_cast<size_t>(std::min<uint64_t>(CHUNK, end - pos));
                const size_t na = nfsReadContent(a.content, a.size, pos, len, bufA.data(), fetch);
                const size_t nb = nfsReadContent(b.content, b.size, pos, len, bufB.data(), fetch);
                same = (na == nb) && memcmp(bufA.data(), bufB.data(), na) == 0;
            }
            done = std::max(done, end);
        }
        if (!same)
            continue;
        LOG_TRACE << "found duplicate versions of " << filename;
        mergeVersionInto(a, b);
        versions.erase(versions.begin() + (i - 1));
    }
    selectedVersion = std::min(selectedVersion, versions.empty() ? 0 : versions.size() - 1);
}


void pcapfs::NfsFile::selectVersion(size_t index) {
    fragments.clear();
    if (versions.empty()) {
        selectedVersion = 0;
        filesizeRaw = filesizeProcessed = 0;
        return;
    }
    selectedVersion = std::min(index, versions.size() - 1);
    const NfsVersion &v = versions.at(selectedVersion);
    fragments.reserve(v.content.size());
    for (const auto &entry : v.content)
        fragments.push_back(entry.second);
    filesizeRaw = filesizeProcessed = v.size;
}


// timestamp mode / snip / snapshot: the semantics mirror SmbFile::constructVersionFiles and
// SmbFile::constructSnapshotFile; the SMB per-operation timestamp maps correspond to the
// version's network candidates (networkStart, READ accesses, networkEnd) and its fsHistory

std::set<pcapfs::TimePoint> pcapfs::NfsFile::networkCandidates(const NfsVersion *v) const {
    std::set<TimePoint> result;
    if (v) {
        result.insert(v->networkStart);
        result.insert(v->accesses.begin(), v->accesses.end());
        result.insert(v->networkEnd);
    } else {
        result.insert(firstSeen);
        result.insert(lastSeen);
        result.insert(observations.begin(), observations.end());
        for (const auto &entry : nodeFsHistory)
            result.insert(entry.first);
    }
    result.erase(TimePoint{});
    return result;
}


std::optional<pcapfs::TimePoint> pcapfs::NfsFile::pickNetworkTime(const std::set<TimePoint> &candidates, const TimePoint *before) {
    for (auto it = candidates.rbegin(); it != candidates.rend(); ++it) {
        if (options::LOWER_SNIP_SPECIFIED && *it < config.snip.first)
            break;      // candidates are sorted: everything older is outside the snip interval too
        if (options::UPPER_SNIP_SPECIFIED && *it >= config.snip.second)
            continue;
        if (before && !(*it < *before))
            continue;
        return *it;
    }
    return std::nullopt;
}


const pcapfs::ServerFileTimestamps *pcapfs::NfsFile::pickFsEntry(const ServerFileTimestampsMap &history, bool applyLower,
                                                                 const TimePoint *valuesBefore) {
    for (auto it = history.rbegin(); it != history.rend(); ++it) {
        if (applyLower && options::LOWER_SNIP_SPECIFIED && it->first < config.snip.first)
            break;
        if (options::UPPER_SNIP_SPECIFIED && it->first >= config.snip.second)
            continue;
        if (valuesBefore && !(it->second < *valuesBefore))
            continue;
        return &it->second;
    }
    return nullptr;
}


void pcapfs::NfsFile::setTimestamps(const NfsVersion *v, const ServerFileTimestamps *fsEntry, const TimePoint &network,
                                    const TimePoint &birthNetwork, const TimePoint *snapshot) {
    if (config.timestampMode == options::TimestampMode::NETWORK) {
        accessTime = modifyTime = changeTime = network;
        birthTime = birthNetwork;
        return;
    }
    const bool hybrid = (config.timestampMode == options::TimestampMode::HYBRID);
    // in snapshot mode the fall-backs must not lie after the snapshot (v->fs and nodeFs hold the latest attrs)
    const auto usable = [&](const TimePoint &t) { return t != TimePoint{} && (!snapshot || t < *snapshot); };
    const auto isSet = [](const TimePoint &t) { return t != TimePoint{} && t != NFS_FS_TIME_INHERITED; };
    const auto pick = [&](TimePoint ServerFileTimestamps::*field, const TimePoint &networkTime, bool earliestOfEntry) {
        if (fsEntry && isSet(fsEntry->*field))
            return fsEntry->*field;
        if (snapshot && earliestOfEntry && fsEntry) {
            // birth time unknown: the earliest time the picked entry knows about
            std::optional<TimePoint> earliest;
            for (const TimePoint &t : {fsEntry->accessTime, fsEntry->modifyTime, fsEntry->changeTime}) {
                if (isSet(t) && (!earliest || t < *earliest))
                    earliest = t;
            }
            if (earliest)
                return *earliest;
        }
        // a version created from its predecessor without an own observation: neither v->fs nor the node's
        // latest attributes (which belong to an older version) apply
        const bool inherited = v && v->fs.*field == NFS_FS_TIME_INHERITED;
        if (!inherited && v && usable(v->fs.*field))
            return v->fs.*field;
        if (!inherited && usable(nodeFs.*field))
            return nodeFs.*field;
        const TimePoint fallback = hybrid ? networkTime + std::chrono::duration_cast<TimePoint::duration>(skew) : networkTime;
        return (snapshot && *snapshot < fallback) ? *snapshot : fallback;
    };
    accessTime = pick(&ServerFileTimestamps::accessTime, network, false);
    modifyTime = pick(&ServerFileTimestamps::modifyTime, network, false);
    changeTime = pick(&ServerFileTimestamps::changeTime, network, false);
    birthTime = pick(&ServerFileTimestamps::birthTime, birthNetwork, true);
}


void pcapfs::NfsFile::updateTimestamps() {
    const NfsVersion *v = versions.empty() ? nullptr : &versions.at(std::min(selectedVersion, versions.size() - 1));
    const ServerFileTimestampsMap &history = v ? v->fsHistory : nodeFsHistory;
    const ServerFileTimestamps *fsEntry = history.empty() ? nullptr : &history.rbegin()->second;
    setTimestamps(v, fsEntry, v ? v->networkEnd : lastSeen, versions.empty() ? firstSeen : versions.front().networkStart);
}


void pcapfs::NfsFile::displayAsMetadataFile() {
    fragments.clear();
    filesizeRaw = filesizeProcessed = 0;
    flags.set(pcapfs::flags::IS_METADATA);
}


pcapfs::TimePoint pcapfs::NfsFile::snapshotNetworkBound() const {
    // FS and HYBRID snapshots are given in server time: a network time t corresponds to t + skew
    return skewed() ? config.snapshot - std::chrono::duration_cast<TimePoint::duration>(skew) : config.snapshot;
}


bool pcapfs::NfsFile::tryMatchTimestampsToSnapshot(const NfsVersion *v) {
    // the version's own observations first, then those of the node
    return matchTimestampsToSnapshot(v) || (v && matchTimestampsToSnapshot(nullptr));
}


bool pcapfs::NfsFile::matchTimestampsToSnapshot(const NfsVersion *v) {
    const std::set<TimePoint> candidates = networkCandidates(v);
    const TimePoint bound = snapshotNetworkBound();
    const TimePoint birthNetwork = versions.empty() ? firstSeen : versions.front().networkStart;
    std::optional<TimePoint> network = pickNetworkTime(candidates, &bound);

    if (config.timestampMode == options::TimestampMode::NETWORK) {
        if (!network)
            return false;
        setTimestamps(v, nullptr, *network, birthNetwork, &config.snapshot);
        return true;
    }

    const ServerFileTimestamps *fsEntry = pickFsEntry(v ? v->fsHistory : nodeFsHistory, true, &config.snapshot);
    if (config.timestampMode == options::TimestampMode::FS) {
        if (!fsEntry)
            return false;
    } else if (!fsEntry && !network) {
        // hybrid: neither an fs observation nor a network observation before the snapshot
        return false;
    }
    if (!network)
        network = candidates.empty() ? TimePoint{} : *candidates.begin();
    setTimestamps(v, fsEntry, *network, birthNetwork, &config.snapshot);
    return true;
}


bool pcapfs::NfsFile::trySetAsMetadataFile(const NfsVersion *v) {
    if (!tryMatchTimestampsToSnapshot(v))
        return false;
    displayAsMetadataFile();
    return true;
}


std::vector<pcapfs::FilePtr> const pcapfs::NfsFile::constructVersionFiles() {
    std::vector<FilePtr> resultVector;
    const bool snip = options::LOWER_SNIP_SPECIFIED || options::UPPER_SNIP_SPECIFIED;

    if (createdInCapture && options::UPPER_SNIP_SPECIFIED && !placements.empty() &&
        !(placements.front().since < config.snip.second)) {
        // the name came into existence after the snip interval: not displayed at all
        donotDisplay = true;
        return resultVector;
    }

    if (versions.size() <= 1 || isDirectory) {
        // metadata file, directory or a single (deduplicated) version: keeps its plain name
        const NfsVersion *v = versions.empty() ? nullptr : &versions.front();
        std::optional<TimePoint> network = pickNetworkTime(networkCandidates(v), nullptr);
        if (!network) {
            if (snip) {
                LOG_DEBUG << filename << " has no matching timestamp in snip interval";
                donotDisplay = true;
                return resultVector;
            }
            network = v ? v->networkEnd : lastSeen;
        }
        selectVersion(0);
        setTimestamps(v, pickFsEntry(v ? v->fsHistory : nodeFsHistory, false, nullptr), *network,
                      v ? v->networkStart : firstSeen);
        return resultVector;
    }

    // multiple file versions: separate file for each version, named like SmbFile does (name@0, name@1, ...)
    // copy the file without its (possibly large) version list, then give each clone only its own version
    std::vector<NfsVersion> allVersions = std::move(versions);
    versions.clear();
    for (size_t i = 0; i < allVersions.size(); ++i) {
        const NfsVersion &currVersion = allVersions.at(i);
        const std::optional<TimePoint> network = pickNetworkTime(networkCandidates(&currVersion), nullptr);
        if (!network)
            continue;   // no access of this version inside the snip interval

        std::shared_ptr<NfsFile> newFile = std::make_shared<NfsFile>(*this);
        newFile->versions = {currVersion};
        // the birth time refers to the first version of the file
        newFile->firstSeen = allVersions.front().networkStart;
        newFile->setFilename(filename + "@" + std::to_string(i));
        newFile->setClientIPs(currVersion.clientIPs);
        newFile->selectVersion(0);
        newFile->setTimestamps(&newFile->versions.front(), pickFsEntry(currVersion.fsHistory, false, nullptr), *network,
                               allVersions.front().networkStart);
        newFile->setIdInIndex(nfs::NfsManager::getInstance().getNewId());
        resultVector.push_back(newFile);
    }
    versions = std::move(allVersions);

    if (resultVector.empty()) {
        // no version was accessed inside the snip interval; the file is still displayed as metadata file
        // when the node itself was observed inside the interval (as SMB does with --show-metadata)
        const std::optional<TimePoint> network = pickNetworkTime(networkCandidates(nullptr), nullptr);
        if (config.showMetadata && network) {
            selectVersion(versions.size() - 1);
            setTimestamps(nullptr, pickFsEntry(nodeFsHistory, false, nullptr), *network, versions.front().networkStart);
            displayAsMetadataFile();
        } else {
            donotDisplay = true;
        }
    }
    return resultVector;
}


void pcapfs::NfsFile::applyPlacementAtSnapshot(const std::map<uint64_t, FilePtr> &byId) {
    if (placements.empty())
        return;
    const TimePoint bound = snapshotNetworkBound();
    // last placement that began at or before the snapshot; the first one if the snapshot precedes all
    size_t chosen = 0;
    for (size_t i = 0; i < placements.size(); ++i) {
        if (!(bound < placements[i].since))
            chosen = i;
    }
    applyPlacement(chosen, byId);
}


void pcapfs::NfsFile::applyFinalPlacement(const std::map<uint64_t, FilePtr> &byId) {
    if (!placements.empty())
        applyPlacement(placements.size() - 1, byId);
}


void pcapfs::NfsFile::applyPlacement(size_t index, const std::map<uint64_t, FilePtr> &byId) {
    const NfsPlacement &p = placements[index];
    if (p.parentId < 0) {
        setFilename(p.name);
        return;
    }
    const auto parent = byId.find(static_cast<uint64_t>(p.parentId));
    if (parent == byId.end())
        return;     // parent is not part of the index: keep the current placement
    setFilename(p.name);
    setParentDir(parent->second);
    setParentDirId(parent->second->getIdInIndex());
}


bool pcapfs::NfsFile::constructSnapshotFile() {
    const TimePoint bound = snapshotNetworkBound();
    if (placementMap)
        applyPlacementAtSnapshot(*placementMap);
    if (createdInCapture && !placements.empty() && bound < placements.front().since)
        return false;   // the name did not exist yet
    if (deleted && deletedAt != TimePoint{} && !(bound < deletedAt))
        return false;   // removed before the snapshot

    if (versions.empty()) {
        // metadata file: select suitable timestamps from the node's observations
        return tryMatchTimestampsToSnapshot(nullptr);
    }

    // select matching file version w.r.t. snapshot time
    size_t target = versions.size();
    for (size_t i = versions.size(); i > 0; --i) {
        const NfsVersion &v = versions[i - 1];
        bool matches;
        if (config.timestampMode == options::TimestampMode::FS && !v.fsHistory.empty()) {
            const ServerFileTimestamps &first = v.fsHistory.begin()->second;
            matches = std::max({first.accessTime, first.modifyTime, first.changeTime}) < config.snapshot;
        } else {
            matches = v.networkStart < bound;
        }
        if (matches) {
            target = i - 1;
            break;
        }
    }

    if (target == versions.size()) {
        // the oldest version is newer than the snapshot time
        if (versions.front().readOrigin) {
            // content observed by a READ existed before -> the first version is still the right one
            target = 0;
        } else {
            // the first version was created in the capture; if the node was seen before the snapshot
            // (e.g. opened without content), display it as metadata file
            return trySetAsMetadataFile(nullptr);
        }
    }

    const NfsVersion &v = versions[target];
    if ((options::LOWER_SNIP_SPECIFIED && config.snip.first > std::max(v.networkStart, v.networkEnd)) ||
        (options::UPPER_SNIP_SPECIFIED && config.snip.second <= v.networkStart)) {
        // version was not accessed inside the snip interval -> only display as empty file (given a suitable timestamp)
        selectVersion(target);
        return trySetAsMetadataFile(&versions[target]);
    }

    if (!tryMatchTimestampsToSnapshot(&v)) {
        LOG_DEBUG << "for nfs file " << filename << ", no matching timestamp could be found";
        return false;
    }
    selectVersion(target);
    return true;
}


void pcapfs::NfsFile::serialize(boost::archive::text_oarchive &archive) {
    ServerFile::serialize(archive);
    archive << versions;
    const uint64_t selected = selectedVersion;
    archive << selected;
    archive << deleted;
    archive << deletedAt;
    archive << firstSeen;
    archive << lastSeen;
    archive << nodeFs;
    const int64_t skewNs = skew.count();
    archive << skewNs;
    archive << nodeFsHistory;
    archive << observations;
    archive << placements;
    archive << createdInCapture;
}


void pcapfs::NfsFile::deserialize(boost::archive::text_iarchive &archive) {
    ServerFile::deserialize(archive);
    archive >> versions;
    uint64_t selected = 0;
    archive >> selected;
    selectedVersion = static_cast<size_t>(selected);
    archive >> deleted;
    archive >> deletedAt;
    archive >> firstSeen;
    archive >> lastSeen;
    archive >> nodeFs;
    int64_t skewNs = 0;
    archive >> skewNs;
    skew = std::chrono::nanoseconds(skewNs);
    archive >> nodeFsHistory;
    archive >> observations;
    archive >> placements;
    archive >> createdInCapture;
}


bool pcapfs::NfsFile::registeredAtFactory =
        pcapfs::FileFactory::registerAtFactory("nfs", pcapfs::NfsFile::create, pcapfs::NfsFile::parse);
