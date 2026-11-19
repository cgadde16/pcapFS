#include "nfs_manager.h"
#include "nfs_stream.h"
#include "../../properties.h"
#include "../../logging.h"

#include <algorithm>
#include <cstdio>
#include <iterator>
#include <memory>
#include <tuple>
#include <unordered_map>
#include <vector>


namespace pcapfs {
    namespace nfs {
        namespace {

            // objects deeper than this below the pseudo-root are not placed in the tree (a path is limited to 4096 bytes)
            constexpr size_t MAX_TREE_DEPTH = 2048;

            // name, or name-2, name-3, ... if it is taken
            std::string uniqueName(const std::set<std::string> &used, std::string name) {
                if (used.count(name)) {
                    const std::string base = name;
                    unsigned k = 1;
                    while (used.count(name))
                        name = base + "-" + std::to_string(++k);
                }
                return name;
            }

            struct Node;

            struct NodePlacement {
                TimePoint since;
                Node *parent;                           // resolved through the alias chain at materialization
                std::string name;
            };

            struct Node {
                Nfsfh4 fh;                              // empty = not yet known
                std::string name;                       // empty for root / unnamed orphans
                Node *parent = nullptr;
                uint32_t type = 0;                      // NF4*, 0 unknown
                std::optional<Fsid4> fsid;
                std::optional<uint64_t> fileid;
                std::map<std::string, Node*> children;  // live children
                std::vector<Node*> removedChildren;     // removed by REMOVE or overwritten by RENAME
                std::string linkTarget;
                std::optional<TimePoint> deletedAt;
                bool hardLink = false;                  // created by LINK; `file` is shared with the link source
                bool dead = false;                      // merged into `alias`
                Node *alias = nullptr;
                NfsFilePtr file;
                std::vector<NodePlacement> placements;  // (parent, name) history, chronological
                bool createdInCapture = false;          // CREATE, OPEN that created the file, LINK
                TimePoint linkSeen = TimePoint{};       // hard links: time of the LINK (the name's own first observation)
            };

            using FileidKey = std::tuple<uint64_t, uint64_t, uint64_t>;

            struct ServerState {
                std::string serverIP;
                std::string srcIP, dstIP, srcPort, dstPort;
                std::set<std::string> clients;
                Node *root = nullptr;
                std::vector<std::unique_ptr<Node>> nodes;
                std::map<Nfsfh4, Node*> byFh;
                std::map<FileidKey, Node*> byFileid;
                std::optional<std::chrono::nanoseconds> skew;
                std::set<const Node*> emitted;          // nodes registered by materialize
                std::set<const NfsFile*> emittedFiles;  // NfsFiles already registered (hard-linked nodes share one until then)
                bool depthWarned = false;               // MAX_TREE_DEPTH exceeded (warned once per server)
            };

            struct Transaction {
                TimePoint time;
                size_t stream;
                size_t index;
            };

            // 64-bit FNV-1a of the whole filehandle as 16 hex digits
            std::string fhHash(const std::string &bytes) {
                uint64_t h = 1469598103934665603ULL;
                for (unsigned char c : bytes) {
                    h ^= c;
                    h *= 1099511628211ULL;
                }
                char b[17];
                snprintf(b, sizeof(b), "%016llx", static_cast<unsigned long long>(h));
                return b;
            }

            // names from the wire become path components: "" / "." / ".." get a placeholder, '/' is replaced
            std::string sanitizeName(const std::string &name) {
                if (name.empty())
                    return "_empty_";
                if (name == ".")
                    return "_dot_";
                if (name == "..")
                    return "_dotdot_";
                std::string result = name;
                for (char &c : result) {
                    const unsigned char u = static_cast<unsigned char>(c);
                    if (c == '/' || u < 0x20 || u == 0x7f)
                        c = '_';
                }
                return result;
            }

            uint64_t piecesLength(const std::vector<NfsContentPiece> &pieces) {
                uint64_t sum = 0;
                for (const NfsContentPiece &p : pieces)
                    sum += p.second.length;
                return sum;
            }

            // the payload copies are not needed after parsing (replay works on pieces/spans only)
            void releasePayloads(NfsStream &stream) {
                for (NfsMessage &m : stream.messages)
                    std::vector<uint8_t>().swap(m.record.bytes);
            }

            TimePoint toTimePoint(const Nfstime4 &t) {
                // seconds comes from the wire as int64: keep it inside what TimePoint can represent
                // (about +-292 years around the epoch) so that the conversion cannot overflow
                constexpr int64_t limit = std::chrono::duration_cast<std::chrono::seconds>(TimePoint::duration::max()).count() - 8;
                const int64_t secs = std::clamp<int64_t>(t.seconds, -limit, limit);
                return TimePoint(std::chrono::duration_cast<TimePoint::duration>(
                        std::chrono::seconds(secs) + std::chrono::nanoseconds(t.nseconds)));
            }

            class Replayer {
            public:
                Replayer(std::vector<ReplayStream> &inStreams) : streams(inStreams) {}

                std::map<std::string, ServerState> states;

                void run(const std::vector<Transaction> &transactions) {
                    for (const Transaction &t : transactions) {
                        ReplayStream &ps = streams[t.stream];
                        auto it = states.find(ps.ep.serverIP);
                        if (it == states.end())
                            continue;
                        const NfsMessage &call = ps.stream.messages[t.index];
                        const NfsMessage *reply = (call.matchedIndex && *call.matchedIndex < ps.stream.messages.size())
                                                  ? &ps.stream.messages[*call.matchedIndex] : nullptr;
                        // a call the server rejected on the RPC level (MSG_DENIED, or accepted with an error such
                        // as GARBAGE_ARGS) was not executed: unlike a call whose reply is missing, it changes nothing
                        if (reply && reply->reply &&
                            (reply->reply->replyStat != MSG_ACCEPTED || reply->reply->acceptStat != 0))
                            continue;
                        if (reply && !reply->res)
                            reply = nullptr;
                        try {
                            replayCompound(it->second, ps, call, reply);
                        } catch (const std::exception &e) {
                            LOG_WARNING << "NFS: skipping a COMPOUND that could not be replayed: " << e.what();
                        }
                    }
                }

                ServerState &stateFor(const ReplayStream &ps) {
                    auto it = states.find(ps.ep.serverIP);
                    if (it != states.end())
                        return it->second;
                    ServerState &s = states[ps.ep.serverIP];
                    s.serverIP = ps.ep.serverIP;
                    s.srcIP = ps.srcIP;
                    s.dstIP = ps.dstIP;
                    s.srcPort = ps.srcPort;
                    s.dstPort = ps.dstPort;
                    s.root = newNode(s, nullptr, "");
                    s.root->type = NF4DIR;
                    return s;
                }

            private:
                std::vector<ReplayStream> &streams;
                TimePoint currentTime = TimePoint{};        // packet time of the compound being replayed

                // records that the node has its current (parent, name) from `time` on
                static void recordPlacement(Node *n, const TimePoint &time) {
                    if (!n->parent)
                        return;
                    Node *p = resolve(n->parent);
                    if (!n->placements.empty()) {
                        const NodePlacement &last = n->placements.back();
                        if (resolve(last.parent) == p && last.name == n->name)
                            return;
                    }
                    n->placements.push_back({time, p, n->name});
                }

                static Node *resolve(Node *n) {
                    while (n && n->alias)
                        n = n->alias;
                    return n;
                }

                static bool isOrphan(const ServerState &s, const Node *n) {
                    return !n->parent && n != s.root;
                }

                // number of ancestors of n (root and orphans: 0); stops counting above MAX_TREE_DEPTH
                static size_t depthOf(const Node *n) {
                    size_t d = 0;
                    for (const Node *p = n->parent; p && d <= MAX_TREE_DEPTH; p = p->parent)
                        ++d;
                    return d;
                }

                void warnDepth(ServerState &s) {
                    if (!s.depthWarned)
                        LOG_WARNING << "NFS: server " << s.serverIP << ": directory tree deeper than " << MAX_TREE_DEPTH
                                    << " levels, deeper objects are placed below unknown-* directories or dropped";
                    s.depthWarned = true;
                }

                Node *newNode(ServerState &s, Node *parent, const std::string &name) {
                    if (parent && depthOf(parent) >= MAX_TREE_DEPTH) {
                        warnDepth(s);
                        parent = nullptr;       // kept as an unnamed orphan instead of extending the chain
                    }
                    s.nodes.push_back(std::make_unique<Node>());
                    Node *n = s.nodes.back().get();
                    n->file = std::make_shared<NfsFile>();
                    if (parent) {
                        n->parent = parent;
                        n->name = name;
                        parent->children[name] = n;
                        if (parent->type == 0)
                            parent->type = NF4DIR;
                        recordPlacement(n, currentTime);
                    }
                    return n;
                }

                Node *childOf(ServerState &s, Node *dir, const std::string &name) {
                    dir = resolve(dir);
                    if (dir->type == 0)
                        dir->type = NF4DIR;
                    auto it = dir->children.find(name);
                    if (it != dir->children.end())
                        return resolve(it->second);
                    return newNode(s, dir, name);
                }

                void removeFromParent(Node *n) {
                    Node *p = n->parent;
                    if (!p)
                        return;
                    auto it = p->children.find(n->name);
                    if (it != p->children.end() && it->second == n)
                        p->children.erase(it);
                    p->removedChildren.erase(std::remove(p->removedChildren.begin(), p->removedChildren.end(), n),
                                             p->removedChildren.end());
                }

                void markRemoved(Node *n, const TimePoint &time) {
                    Node *p = n->parent;
                    n->deletedAt = time;
                    if (!p)
                        return;
                    auto it = p->children.find(n->name);
                    if (it != p->children.end() && it->second == n)
                        p->children.erase(it);
                    if (std::find(p->removedChildren.begin(), p->removedChildren.end(), n) == p->removedChildren.end())
                        p->removedChildren.push_back(n);
                }

                // true if a is a proper ancestor of b
                static bool isAncestor(const Node *a, const Node *b) {
                    size_t guard = 0;
                    for (const Node *p = b->parent; p && guard < 1000000; p = p->parent, ++guard) {
                        if (p == a)
                            return true;
                    }
                    return false;
                }

                static constexpr unsigned MAX_MERGE_DEPTH = 2048;

                // keep absorbs drop; if keep is an unnamed orphan it takes over drop's place in the tree. The root is never
                // dropped. Returns false if the merge would create a parent cycle. Subtrees with the same names are merged
                // recursively up to MAX_MERGE_DEPTH, a deeper subtree is emitted as an orphan
                bool mergeNodes(ServerState &s, Node *keep, Node *drop, unsigned depth = 0) {
                    keep = resolve(keep);
                    drop = resolve(drop);
                    if (keep == drop)
                        return true;
                    if (depth > MAX_MERGE_DEPTH) {
                        LOG_WARNING << "NFS: directory tree is nested deeper than " << MAX_MERGE_DEPTH
                                    << " levels, not merging below that";
                        return false;
                    }
                    if (drop == s.root)
                        std::swap(keep, drop);
                    if (isAncestor(keep, drop) || isAncestor(drop, keep))
                        return false;
                    drop->alias = keep;
                    drop->dead = true;

                    if (drop->parent) {
                        Node *p = drop->parent;
                        if (isOrphan(s, keep)) {
                            auto it = p->children.find(drop->name);
                            if (it != p->children.end() && it->second == drop)
                                it->second = keep;
                            std::replace(p->removedChildren.begin(), p->removedChildren.end(), drop, keep);
                            keep->parent = p;
                            keep->name = drop->name;
                        } else {
                            removeFromParent(drop);
                        }
                    }
                    // the recursive merges below modify the child maps, so take them over first
                    const std::map<std::string, Node*> dropChildren = std::move(drop->children);
                    drop->children.clear();
                    for (const auto &child : dropChildren) {
                        auto existing = keep->children.find(child.first);
                        if (existing == keep->children.end()) {
                            keep->children[child.first] = child.second;
                            child.second->parent = keep;
                        } else {
                            // same name on both sides: one object, merge the subtrees
                            mergeNodes(s, existing->second, child.second, depth + 1);
                        }
                    }
                    const std::vector<Node*> dropRemoved = std::move(drop->removedChildren);
                    drop->removedChildren.clear();
                    for (Node *removed : dropRemoved) {
                        removed->parent = keep;
                        keep->removedChildren.push_back(removed);
                    }

                    // the survivor keeps the union of both placement histories (chronological, no repeats)
                    if (!drop->placements.empty()) {
                        keep->placements.insert(keep->placements.end(), drop->placements.begin(), drop->placements.end());
                        std::stable_sort(keep->placements.begin(), keep->placements.end(),
                                         [](const NodePlacement &a, const NodePlacement &b) { return a.since < b.since; });
                        drop->placements.clear();
                    }
                    keep->createdInCapture = keep->createdInCapture || drop->createdInCapture;
                    if (keep->linkSeen == TimePoint{})
                        keep->linkSeen = drop->linkSeen;

                    if (keep->fh.empty())
                        keep->fh = drop->fh;
                    if (!keep->fsid)
                        keep->fsid = drop->fsid;
                    if (!keep->fileid)
                        keep->fileid = drop->fileid;
                    if (keep->type == 0)
                        keep->type = drop->type;
                    if (keep->linkTarget.empty())
                        keep->linkTarget = drop->linkTarget;
                    if (!keep->deletedAt)
                        keep->deletedAt = drop->deletedAt;
                    keep->hardLink = keep->hardLink || drop->hardLink;
                    if (keep->type == 0 && !keep->children.empty())
                        keep->type = NF4DIR;

                    for (auto &kv : s.byFh)
                        if (kv.second == drop)
                            kv.second = keep;
                    for (auto &kv : s.byFileid)
                        if (kv.second == drop)
                            kv.second = keep;

                    if (keep->file == drop->file)
                        return true;        // hard links of one object: nothing to merge
                    // other hard links of drop share drop's file: they follow keep's file from now on
                    if (drop->file.use_count() > 1) {
                        for (auto &node : s.nodes)
                            if (node.get() != drop && node->file == drop->file)
                                node->file = keep->file;
                    }
                    NfsFile &kf = *keep->file;
                    NfsFile &df = *drop->file;
                    if (kf.versions.empty()) {
                        kf.versions = std::move(df.versions);
                    } else if (!df.versions.empty()) {
                        kf.versions.insert(kf.versions.end(), df.versions.begin(), df.versions.end());
                        std::stable_sort(kf.versions.begin(), kf.versions.end(), [](const NfsVersion &a, const NfsVersion &b) {
                            return a.networkStart < b.networkStart;
                        });
                        kf.mergeIdenticalVersions();
                    }
                    if (df.firstSeen != TimePoint{} && (kf.firstSeen == TimePoint{} || df.firstSeen < kf.firstSeen))
                        kf.firstSeen = df.firstSeen;
                    kf.lastSeen = std::max(kf.lastSeen, df.lastSeen);
                    for (const auto &ip : df.getClientIPs())
                        kf.addClientIP(ip);
                    const ServerFileTimestamps &d = df.nodeFs;
                    ServerFileTimestamps &k = kf.nodeFs;
                    if (k.accessTime == TimePoint{})
                        k.accessTime = d.accessTime;
                    if (k.modifyTime == TimePoint{})
                        k.modifyTime = d.modifyTime;
                    if (k.changeTime == TimePoint{})
                        k.changeTime = d.changeTime;
                    if (k.birthTime == TimePoint{})
                        k.birthTime = d.birthTime;
                    for (const auto &entry : df.nodeFsHistory)
                        nfsRecordFsTimes(kf.nodeFsHistory, entry.first, entry.second);
                    kf.observations.insert(df.observations.begin(), df.observations.end());
                    for (const char *key : {"mode", "owner", "group"}) {
                        if (kf.getProperty(key).empty() && !df.getProperty(key).empty())
                            kf.setProperty(key, df.getProperty(key));
                    }
                    return true;
                }

                Node *orphanForFh(ServerState &s, const Nfsfh4 &fh) {
                    auto it = s.byFh.find(fh);
                    if (it != s.byFh.end())
                        return resolve(it->second);
                    Node *n = newNode(s, nullptr, "");
                    n->fh = fh;
                    s.byFh[fh] = n;
                    return n;
                }

                // gives n the filehandle fh; returns the node that represents the object from now on
                Node *assignFh(ServerState &s, Node *n, const Nfsfh4 &fh, const TimePoint &time) {
                    n = resolve(n);
                    auto it = s.byFh.find(fh);
                    Node *other = (it != s.byFh.end()) ? resolve(it->second) : nullptr;
                    if (n->fh == fh) {
                        if (!other)
                            s.byFh[fh] = n;
                        return n;
                    }
                    if (n->fh.empty()) {
                        if (!other || other == n) {
                            n->fh = fh;
                            s.byFh[fh] = n;
                            return n;
                        }
                        if (other->deletedAt && other->file.use_count() <= 1) {
                            // the filehandle belonged to a name that was REMOVEd or replaced: n is a different object
                            // (not if the removed name was a hard link whose content is still shared with another
                            // name: then the filehandle is still in use by that object)
                            n->fh = fh;
                            s.byFh[fh] = n;
                            return n;
                        }
                        const bool nNamed = !isOrphan(s, n);
                        const bool oNamed = !isOrphan(s, other);
                        if (nNamed && oNamed && other != s.root && n != s.root) {
                            // two names for one object (hard link or unseen rename): keep both nodes
                            n->fh = fh;
                            return n;
                        }
                        if (!mergeNodes(s, other, n)) {
                            n->fh = fh;     // would create a cycle: keep both nodes
                            return n;
                        }
                        return resolve(other);
                    }
                    // the node already has a different filehandle
                    if (n->parent && n != s.root) {
                        // a different object now lives under this name: the old one was replaced
                        Node *old = n;
                        Node *parent = old->parent;
                        const std::string name = old->name;
                        markRemoved(old, time);
                        Node *fresh;
                        if (other && other->deletedAt && other->file.use_count() <= 1)
                            other = nullptr;    // reused filehandle of a removed name: the object under this name is new
                        if (other && isOrphan(s, other) && (other == parent || isAncestor(other, parent))) {
                            LOG_WARNING << "NFS: not moving '" << name << "' below its own subtree (filehandle graph would become cyclic)";
                            fresh = other;
                        } else if (other && isOrphan(s, other)) {
                            other->parent = parent;
                            other->name = name;
                            parent->children[name] = other;
                            recordPlacement(other, time);
                            fresh = other;
                        } else if (other) {
                            fresh = other;
                        } else {
                            fresh = newNode(s, parent, name);
                            fresh->fh = fh;
                            s.byFh[fh] = fresh;
                        }
                        return fresh;
                    }
                    return orphanForFh(s, fh);
                }

                std::optional<Fsid4> effectiveFsid(const Node *n) const {
                    for (; n; n = n->parent) {
                        if (n->fsid)
                            return n->fsid;
                    }
                    return std::nullopt;
                }

                Node *mergeByFileid(ServerState &s, Node *n) {
                    n = resolve(n);
                    const auto fsid = effectiveFsid(n);
                    if (!fsid || !n->fileid)
                        return n;
                    const FileidKey key{fsid->major, fsid->minor, *n->fileid};
                    auto it = s.byFileid.find(key);
                    Node *other = (it != s.byFileid.end()) ? resolve(it->second) : nullptr;
                    if (!other || other == n || other->dead) {
                        s.byFileid[key] = n;
                        return n;
                    }
                    // a reused inode number after REMOVE: different filehandle or a removed node is another object
                    if ((!n->fh.empty() && !other->fh.empty() && n->fh != other->fh) || other->deletedAt) {
                        s.byFileid[key] = n;
                        return n;
                    }
                    const bool nOrphan = isOrphan(s, n);
                    const bool oOrphan = isOrphan(s, other);
                    if (oOrphan && !nOrphan) {
                        if (mergeNodes(s, n, other))
                            s.byFileid[key] = n;
                        return resolve(n);
                    }
                    if (nOrphan) {
                        if (!mergeNodes(s, other, n))
                            return n;
                        return resolve(other);
                    }
                    return n;   // two named nodes with one fileid: hard links, keep both
                }

                Node *applyAttrs(ServerState &s, Node *n, const Fattr4 &attrs, const TimePoint &time, const std::string &clientIP) {
                    n = resolve(n);
                    if (attrs.type && *attrs.type != 0)
                        n->type = *attrs.type;
                    if (attrs.fsid)
                        n->fsid = attrs.fsid;
                    if (attrs.fileid)
                        n->fileid = attrs.fileid;
                    if (attrs.filehandle)
                        n = assignFh(s, n, *attrs.filehandle, time);
                    n = mergeByFileid(s, n);
                    NfsFile &f = *n->file;
                    f.touch(time, clientIP);
                    if (attrs.size && n->type != NF4DIR)
                        f.applySizeAttr(*attrs.size);
                    TimePoint a, m, c, b;
                    if (attrs.timeAccess)
                        a = toTimePoint(*attrs.timeAccess);
                    if (attrs.timeModify)
                        m = toTimePoint(*attrs.timeModify);
                    if (attrs.timeMetadata)
                        c = toTimePoint(*attrs.timeMetadata);
                    if (attrs.timeCreate)
                        b = toTimePoint(*attrs.timeCreate);
                    if (attrs.timeAccess || attrs.timeModify || attrs.timeMetadata || attrs.timeCreate)
                        f.applyFsTimes(time, attrs.timeAccess ? &a : nullptr, attrs.timeModify ? &m : nullptr,
                                       attrs.timeMetadata ? &c : nullptr, attrs.timeCreate ? &b : nullptr);
                    if (attrs.mode) {
                        char buf[16];
                        snprintf(buf, sizeof(buf), "%04o", *attrs.mode & 07777);
                        f.setProperty("mode", buf);
                    }
                    if (attrs.owner)
                        f.setProperty("owner", *attrs.owner);
                    if (attrs.ownerGroup)
                        f.setProperty("group", *attrs.ownerGroup);
                    return n;
                }

                static std::vector<NfsContentPiece> piecesOf(const ReplayStream &ps, const NfsMessage &m, const Span &span,
                                                              uint64_t fileOffset) {
                    std::vector<NfsContentPiece> result;
                    uint64_t acc = 0;
                    for (const Piece &p : m.record.piecesFor(m.compoundOffset + span.offset, span.length)) {
                        Fragment frag;
                        frag.id = ps.tcpId;
                        frag.start = p.bufferOffset;
                        frag.length = p.length;
                        result.emplace_back(fileOffset + acc, frag);
                        acc += p.length;
                    }
                    return result;
                }

                // ops that do not change the current or saved filehandle
                static bool leavesFhUnchanged(uint32_t o) {
                    switch (o) {
                        case op::SEQUENCE: case op::ACCESS: case op::GETATTR: case op::GETFH: case op::COMMIT:
                        case op::SETATTR: case op::READ: case op::READDIR: case op::READLINK: case op::READ_PLUS:
                        case op::CLOSE: case op::VERIFY: case op::NVERIFY: case op::LOCK: case op::LOCKT:
                        case op::LOCKU: case op::OPEN_CONFIRM: case op::OPEN_DOWNGRADE: case op::REMOVE:
                        case op::RENAME: case op::LINK: case op::SEEK: case op::ALLOCATE: case op::DEALLOCATE:
                        case op::IO_ADVISE: case op::DELEGRETURN: case op::RENEW:
                            return true;
                        default:
                            return false;
                    }
                }

                static void clipPieces(std::vector<NfsContentPiece> &pieces, uint64_t limit) {
                    uint64_t acc = 0;
                    for (size_t i = 0; i < pieces.size(); ++i) {
                        Fragment &f = pieces[i].second;
                        if (acc >= limit) {
                            pieces.resize(i);
                            return;
                        }
                        if (acc + f.length > limit)
                            f.length = limit - acc;
                        acc += f.length;
                    }
                }

                void truncateFile(Node *n, uint64_t size, const TimePoint &time, const std::string &clientIP) {
                    if (n->type == 0)
                        n->type = NF4REG;
                    n->file->applyTruncate(size, time, clientIP);
                }

                // ALLOCATE (grow with zeros) / DEALLOCATE (punch a hole) on the current filehandle
                void applyRange(Node *n, uint32_t o, const RangeArgs &x, const TimePoint &time, const std::string &clientIP) {
                    if (n->type == 0)
                        n->type = NF4REG;
                    if (o == op::DEALLOCATE)
                        n->file->applyDeallocate(x.offset, x.length, time, clientIP);
                    else
                        n->file->applyAllocate(x.offset, x.length, time, clientIP);
                }

                void replayCompound(ServerState &s, ReplayStream &ps, const NfsMessage &call, const NfsMessage *reply) {
                    if (!call.isCall || !call.isNfs4 || call.retransmission || !call.args)
                        return;
                    const TimePoint time = call.record.time;
                    currentTime = time;
                    const TimePoint replyTime = reply ? reply->record.time : time;
                    const std::string &clientIP = ps.ep.clientIP;
                    s.clients.insert(clientIP);
                    const CompoundRes *res = reply ? &*reply->res : nullptr;

                    Node *cfh = nullptr;
                    Node *sfh = nullptr;
                    bool sawWrite = false;
                    std::optional<Nfstime4> serverTime;

                    const auto &ops = call.args->ops;
                    for (size_t i = 0; i < ops.size(); ++i) {
                        const ArgOp &a = ops[i];
                        const ResOp *r = (res && i < res->ops.size()) ? &res->ops[i] : nullptr;
                        if (!res) {
                            // no reply at all: navigation (as far as the graph already knows the names), content
                            // modifications and fh-neutral ops are applied; stop at the first op whose result would be
                            // needed to continue (OPEN claim-by-name, CREATE, ...)
                            if (a.op == op::PUTFH) {
                                if (auto *x = std::get_if<PutfhArgs>(&a.args))
                                    cfh = orphanForFh(s, x->fh);
                            } else if (a.op == op::PUTROOTFH || a.op == op::PUTPUBFH) {
                                cfh = s.root;
                            } else if (a.op == op::SAVEFH) {
                                sfh = cfh;
                            } else if (a.op == op::RESTOREFH) {
                                cfh = sfh;
                            } else if (a.op == op::LOOKUP) {
                                auto *x = std::get_if<NameArgs>(&a.args);
                                if (!x || !cfh || !resolve(cfh)->children.count(x->name))
                                    break;
                                cfh = childOf(s, cfh, x->name);
                            } else if (a.op == op::LOOKUPP) {
                                if (!cfh || !resolve(cfh)->parent)
                                    break;
                                cfh = resolve(resolve(cfh)->parent);
                            } else if (a.op == op::WRITE) {
                                if (auto *x = std::get_if<WriteArgs>(&a.args); x && cfh) {
                                    cfh = resolve(cfh);
                                    if (cfh->type == 0)
                                        cfh->type = NF4REG;
                                    auto pieces = piecesOf(ps, call, x->data, x->offset);
                                    if (nfsRangeValid(x->offset, piecesLength(pieces)))
                                        cfh->file->applyWrite(pieces, x->offset + piecesLength(pieces), time, clientIP);
                                }
                            } else if (a.op == op::ALLOCATE || a.op == op::DEALLOCATE) {
                                if (auto *x = std::get_if<RangeArgs>(&a.args); x && cfh) {
                                    cfh = resolve(cfh);
                                    applyRange(cfh, a.op, *x, time, clientIP);
                                }
                            } else if (!leavesFhUnchanged(a.op)) {
                                break;      // OPEN, CREATE, ...: the resulting current filehandle is unknown
                            }
                            continue;
                        }
                        if (!r || r->op != a.op || r->status != NFS4_OK)
                            break;
                        if (cfh)
                            cfh = resolve(cfh);
                        if (sfh)
                            sfh = resolve(sfh);

                        switch (a.op) {
                            case op::PUTROOTFH:
                            case op::PUTPUBFH:
                                cfh = s.root;
                                break;
                            case op::PUTFH:
                                if (auto *x = std::get_if<PutfhArgs>(&a.args))
                                    cfh = orphanForFh(s, x->fh);
                                break;
                            case op::SAVEFH:
                                sfh = cfh;
                                break;
                            case op::RESTOREFH:
                                cfh = sfh;
                                break;
                            case op::LOOKUP:
                                if (auto *x = std::get_if<NameArgs>(&a.args); x && cfh) {
                                    cfh = childOf(s, cfh, x->name);
                                    cfh->file->touch(time, clientIP);
                                }
                                break;
                            case op::LOOKUPP:
                                if (cfh && cfh->parent)
                                    cfh = resolve(cfh->parent);
                                else
                                    cfh = nullptr;
                                break;
                            case op::GETFH:
                                if (auto *x = std::get_if<GetfhRes>(&r->res); x && cfh)
                                    cfh = assignFh(s, cfh, x->fh, time);
                                break;
                            case op::OPEN:
                                if (auto *x = std::get_if<OpenArgs>(&a.args); x && cfh) {
                                    Node *file = cfh;
                                    if (x->claimType == CLAIM_NULL || x->claimType == CLAIM_DELEGATE_CUR || x->claimType == CLAIM_DELEGATE_PREV)
                                        file = childOf(s, cfh, x->file);
                                    if (file->type == 0 || file->type == NF4DIR)
                                        file->type = NF4REG;
                                    file->file->touch(time, clientIP);
                                    cfh = file;
                                    if (x->openType == OPEN4_CREATE) {
                                        // the directory's change attribute moves only if the open created the file
                                        if (auto *o = std::get_if<OpenRes>(&r->res); o && o->cinfo.before != o->cinfo.after)
                                            file->createdInCapture = true;
                                        const bool exclusive = (x->createMode == EXCLUSIVE4 || x->createMode == EXCLUSIVE4_1);
                                        const bool sizeZero = x->createAttrs && x->createAttrs->size && *x->createAttrs->size == 0;
                                        if (sizeZero || exclusive)
                                            truncateFile(cfh, 0, time, clientIP);
                                        if (x->createAttrs) {
                                            Fattr4 attrs = *x->createAttrs;
                                            attrs.size.reset();
                                            cfh = applyAttrs(s, cfh, attrs, time, clientIP);
                                        }
                                    }
                                }
                                break;
                            case op::CREATE:
                                if (auto *x = std::get_if<CreateArgs>(&a.args); x && cfh) {
                                    // CREATE only succeeds if the name does not exist: a live child is stale
                                    Node *dir = resolve(cfh);
                                    if (dir->type == 0)
                                        dir->type = NF4DIR;
                                    auto stale = dir->children.find(x->name);
                                    if (stale != dir->children.end())
                                        markRemoved(resolve(stale->second), time);
                                    Node *child = newNode(s, dir, x->name);
                                    child->createdInCapture = true;
                                    child->type = x->objType;
                                    if (x->objType == NF4LNK) {
                                        child->linkTarget = x->linkdata;
                                    }
                                    child->file->touch(time, clientIP);
                                    cfh = applyAttrs(s, child, x->attrs, time, clientIP);
                                }
                                break;
                            case op::GETATTR:
                                if (auto *x = std::get_if<GetattrRes>(&r->res); x && cfh) {
                                    cfh = applyAttrs(s, cfh, x->attrs, replyTime, clientIP);
                                    if (x->attrs.timeMetadata)
                                        serverTime = x->attrs.timeMetadata;
                                }
                                break;
                            case op::READDIR:
                                if (auto *x = std::get_if<ReaddirRes>(&r->res); x && cfh) {
                                    Node *dir = cfh;
                                    for (const DirEntry4 &e : x->entries) {
                                        Node *child = childOf(s, dir, e.name);
                                        applyAttrs(s, child, e.attrs, replyTime, clientIP);
                                    }
                                }
                                break;
                            case op::READLINK:
                                if (auto *x = std::get_if<ReadlinkRes>(&r->res); x && cfh) {
                                    cfh->type = NF4LNK;
                                    cfh->linkTarget = x->link;
                                    cfh->file->touch(replyTime, clientIP);
                                }
                                break;
                            case op::READ:
                                if (auto *x = std::get_if<ReadArgs>(&a.args); x && cfh) {
                                    if (auto *rr = std::get_if<ReadRes>(&r->res)) {
                                        if (cfh->type == 0)
                                            cfh->type = NF4REG;
                                        auto pieces = piecesOf(ps, *reply, rr->data, x->offset);
                                        if (nfsRangeValid(x->offset, piecesLength(pieces)))
                                            cfh->file->applyRead(pieces, x->offset + piecesLength(pieces), replyTime, clientIP);
                                    }
                                }
                                break;
                            case op::READ_PLUS:
                                if (cfh) {
                                    if (auto *rr = std::get_if<ReadPlusRes>(&r->res)) {
                                        if (cfh->type == 0)
                                            cfh->type = NF4REG;
                                        for (const ReadPlusContent &c : rr->contents) {
                                            if (c.type == NFS4_CONTENT_DATA) {
                                                auto pieces = piecesOf(ps, *reply, c.data, c.offset);
                                                if (nfsRangeValid(c.offset, piecesLength(pieces)))
                                                    cfh->file->applyRead(pieces, c.offset + piecesLength(pieces), replyTime, clientIP);
                                            } else if (nfsRangeValid(c.offset, c.length)) {
                                                cfh->file->applyHole(c.offset, c.length, replyTime, clientIP);
                                                cfh->file->applyClose();
                                            }
                                        }
                                        if (rr->contents.empty())
                                            cfh->file->applyRead({}, 0, replyTime, clientIP);
                                    }
                                }
                                break;
                            case op::WRITE:
                                if (auto *x = std::get_if<WriteArgs>(&a.args); x && cfh) {
                                    if (cfh->type == 0)
                                        cfh->type = NF4REG;
                                    auto pieces = piecesOf(ps, call, x->data, x->offset);
                                    if (auto *wr = std::get_if<WriteRes>(&r->res); wr && wr->count < piecesLength(pieces))
                                        clipPieces(pieces, wr->count);
                                    if (nfsRangeValid(x->offset, piecesLength(pieces)))
                                        cfh->file->applyWrite(pieces, x->offset + piecesLength(pieces), time, clientIP);
                                    sawWrite = true;
                                }
                                break;
                            case op::SETATTR:
                                if (auto *x = std::get_if<SetattrArgs>(&a.args); x && cfh) {
                                    if (x->attrs.size)
                                        truncateFile(cfh, *x->attrs.size, time, clientIP);
                                    Fattr4 attrs = x->attrs;
                                    attrs.size.reset();
                                    cfh = applyAttrs(s, cfh, attrs, time, clientIP);
                                }
                                break;
                            case op::CLOSE:
                                if (cfh)
                                    cfh->file->applyClose();
                                break;
                            case op::REMOVE:
                                if (auto *x = std::get_if<NameArgs>(&a.args); x && cfh) {
                                    Node *dir = resolve(cfh);
                                    auto it = dir->children.find(x->name);
                                    if (it != dir->children.end()) {    // never seen name: nothing to mark
                                        Node *child = resolve(it->second);
                                        markRemoved(child, time);
                                        child->file->touch(time, clientIP);
                                    }
                                }
                                break;
                            case op::RENAME:
                                if (auto *x = std::get_if<RenameArgs>(&a.args); x && cfh && sfh) {
                                    Node *src = childOf(s, sfh, x->oldname);
                                    if (src == cfh || isAncestor(src, cfh)) {
                                        LOG_WARNING << "NFS: ignoring RENAME of '" << x->oldname << "' into its own subtree";
                                        break;
                                    }
                                    auto existing = cfh->children.find(x->newname);
                                    if (existing != cfh->children.end() && resolve(existing->second) != src)
                                        markRemoved(resolve(existing->second), time);
                                    removeFromParent(src);
                                    src->parent = cfh;
                                    src->name = x->newname;
                                    cfh->children[x->newname] = src;
                                    recordPlacement(src, time);
                                    if (cfh->type == 0)
                                        cfh->type = NF4DIR;
                                    src->file->touch(time, clientIP);
                                }
                                break;
                            case op::LINK:
                                if (auto *x = std::get_if<NameArgs>(&a.args); x && cfh && sfh && sfh != s.root) {
                                    // a hard link is another name of the same object: the new node shares the
                                    // source's NfsFile (content, versions, attrs); materialize clones it per name
                                    Node *dir = resolve(cfh);
                                    if (dir->type == 0)
                                        dir->type = NF4DIR;
                                    auto stale = dir->children.find(x->name);
                                    // decided before markRemoved: it erases the map entry stale points to
                                    const bool isNewName = stale == dir->children.end() || resolve(stale->second) != sfh;
                                    if (stale != dir->children.end() && isNewName)
                                        markRemoved(resolve(stale->second), time);    // LINK fails if the name exists
                                    if (isNewName) {
                                        Node *link = newNode(s, dir, x->name);
                                        link->hardLink = true;
                                        link->createdInCapture = true;
                                        link->linkSeen = time;
                                        link->type = sfh->type == NF4DIR ? 0 : sfh->type;
                                        link->fsid = sfh->fsid;
                                        link->fileid = sfh->fileid;
                                        link->linkTarget = sfh->linkTarget;
                                        link->file = sfh->file;
                                    }
                                    if (sfh->type == 0)
                                        sfh->type = NF4REG;
                                    sfh->file->touch(time, clientIP);
                                }
                                break;
                            case op::ALLOCATE:
                            case op::DEALLOCATE:
                                if (auto *x = std::get_if<RangeArgs>(&a.args); x && cfh)
                                    applyRange(cfh, a.op, *x, time, clientIP);
                                break;
                            case op::CLONE:
                                if (auto *x = std::get_if<CloneArgs>(&a.args); x && cfh && sfh) {
                                    cloneContent(cfh, sfh, x->srcOffset, x->dstOffset, x->count, time, clientIP);
                                }
                                break;
                            case op::COPY:
                                if (auto *x = std::get_if<CopyArgs>(&a.args); x && cfh && sfh) {
                                    uint64_t count = x->count;
                                    if (auto *cr = std::get_if<CopyRes>(&r->res); cr && cr->count > 0)
                                        count = cr->count;
                                    cloneContent(cfh, sfh, x->srcOffset, x->dstOffset, count, replyTime, clientIP);
                                }
                                break;
                            case op::OPENATTR:
                                // the current filehandle is now the named attribute directory of the file, which
                                // is not modelled: ops that need it are skipped until the next PUTFH/PUTROOTFH
                                cfh = nullptr;
                                break;
                            default:
                                break;
                        }
                        if (!cfh && (a.op == op::LOOKUPP || a.op == op::LOOKUP || a.op == op::PUTFH))
                            break;
                    }

                    if (!s.skew && sawWrite && serverTime)
                        s.skew = std::chrono::duration_cast<std::chrono::nanoseconds>(toTimePoint(*serverTime) - replyTime);
                }

                void cloneContent(Node *dst, Node *src, uint64_t srcOffset, uint64_t dstOffset, uint64_t count,
                                  const TimePoint &time, const std::string &clientIP) {
                    if (dst->type == 0)
                        dst->type = NF4REG;
                    // copy the source map first: src and dst may be the same file
                    NfsContentMap srcContent;
                    uint64_t srcSize = 0;
                    if (!src->file->versions.empty()) {
                        srcContent = src->file->versions.back().content;
                        srcSize = src->file->versions.back().size;
                    }
                    dst->file->applyClone(srcContent, srcSize, srcOffset, dstOffset, count, time, clientIP);
                }

            public:

                void materialize(ServerState &s, ServerFileRegistry &registry,
                                 const std::function<uint64_t()> &newId) {
                    s.root = resolve(s.root);
                    Node *root = s.root;
                    NfsFile &rf = *root->file;
                    rf.setFilename(s.serverIP);
                    rf.isDirectory = true;
                    decorate(s, root, nullptr, s.serverIP, newId, registry);

                    // orphans: live nodes the walk from the root did not reach (no parent, or a parent that is gone).
                    // Each is emitted below the topmost unemitted ancestor so that the order of s.nodes does not matter.
                    std::vector<Node*> orphans;
                    std::set<Node*> orphanSet;
                    std::unordered_map<Node*, Node*> topOf;
                    std::vector<Node*> climbed;
                    for (auto &n : s.nodes) {
                        if (n->dead || n.get() == root || s.emitted.count(n.get()))
                            continue;
                        // climb to the topmost unemitted ancestor; the result is remembered for every node on the
                        // way, so that a deep chain is climbed once and not once per node
                        Node *top = n.get();
                        climbed.clear();
                        size_t guard = 0;
                        for (;;) {
                            const auto known = topOf.find(top);
                            if (known != topOf.end()) {
                                top = known->second;
                                break;
                            }
                            if (!top->parent || top->parent->dead || s.emitted.count(top->parent) || guard++ >= 1000000)
                                break;
                            climbed.push_back(top);
                            top = top->parent;
                        }
                        for (Node *below : climbed)
                            topOf[below] = top;
                        if (orphanSet.insert(top).second)
                            orphans.push_back(top);
                    }
                    std::set<std::string> used;
                    for (const auto &c : root->children)
                        used.insert(c.first);
                    for (Node *r : root->removedChildren)
                        used.insert(r->name);
                    size_t anonymous = 0;
                    for (Node *o : orphans) {
                        if (s.emitted.count(o))     // already emitted below an earlier orphan
                            continue;
                        std::string name = o->fh.empty() ? "unknown-id" + std::to_string(++anonymous)
                                                          : "unknown-" + fhHash(o->fh).substr(0, 8);
                        name = uniqueName(used, name);
                        used.insert(name);
                        decorate(s, o, root, name, newId, registry);
                    }
                    resolvePlacements(s);
                }

            private:
                // turns the node placements into NfsFile placements (parent node -> idInIndex of its file); done after
                // the whole tree is emitted because a placement may refer to a parent that is emitted later
                void resolvePlacements(ServerState &s) {
                    for (auto &np : s.nodes) {
                        Node *n = np.get();
                        if (n->dead || !s.emitted.count(n) || n->placements.empty())
                            continue;
                        NfsFile &f = *n->file;
                        std::vector<NfsPlacement> result;
                        for (const NodePlacement &p : n->placements) {
                            const Node *parent = resolve(p.parent);
                            if (!parent || !s.emitted.count(parent))
                                continue;
                            NfsPlacement entry;
                            entry.since = p.since;
                            entry.parentId = static_cast<int64_t>(parent->file->getIdInIndex());
                            entry.name = sanitizeName(p.name);
                            if (!result.empty() && result.back().parentId == entry.parentId && result.back().name == entry.name)
                                continue;
                            result.push_back(std::move(entry));
                        }
                        if (result.empty())
                            continue;
                        // the last placement has to match the materialized parent directory; it keeps the plain wire name
                        // (display suffixes like @deleted belong to the all-time view)
                        if (result.back().parentId != static_cast<int64_t>(f.getParentDirId())) {
                            NfsPlacement last;
                            last.since = result.back().since;
                            last.parentId = static_cast<int64_t>(f.getParentDirId());
                            last.name = result.back().name;
                            result.push_back(std::move(last));
                        }
                        f.placements = std::move(result);
                    }
                }

                struct DecorateItem {
                    Node *node;
                    Node *parent;
                    std::string displayName;
                    size_t depth;       // levels below the node the walk started at
                };

                // emits n and everything below it in pre-order (children by name, then removed children) with an explicit
                // stack; nodes deeper than MAX_TREE_DEPTH below the start are dropped
                void decorate(ServerState &s, Node *start, Node *startParent, const std::string &startName,
                              const std::function<uint64_t()> &newId,
                              ServerFileRegistry &registry) {
                    std::vector<DecorateItem> stack;
                    stack.push_back({start, startParent, startName, 0});
                    std::vector<DecorateItem> below;
                    while (!stack.empty()) {
                        const DecorateItem item = std::move(stack.back());
                        stack.pop_back();
                        if (item.depth > MAX_TREE_DEPTH) {
                            warnDepth(s);
                            continue;
                        }
                        below.clear();
                        decorateNode(s, item.node, item.parent, item.displayName, newId, registry, below);
                        for (DecorateItem &b : below)
                            b.depth = item.depth + 1;
                        // reversed, so that the first child is emitted next
                        stack.insert(stack.end(), std::make_move_iterator(below.rbegin()),
                                     std::make_move_iterator(below.rend()));
                    }
                }

                // emits one node and appends the nodes below it to `below` in emission order
                void decorateNode(ServerState &s, Node *n, Node *parent, const std::string &displayName,
                                  const std::function<uint64_t()> &newId,
                                  ServerFileRegistry &registry,
                                  std::vector<DecorateItem> &below) {
                    if (!s.emitted.insert(n).second)
                        return;             // emission is idempotent per node
                    // hard-linked names share one NfsFile during the replay; every name gets its own copy so that filename,
                    // parent, id and deletion can differ
                    if (n->hardLink || !s.emittedFiles.insert(n->file.get()).second) {
                        n->file = std::make_shared<NfsFile>(*n->file);
                        s.emittedFiles.insert(n->file.get());
                    }
                    NfsFile &f = *n->file;
                    if (n->hardLink && n->linkSeen != TimePoint{}) {
                        // the new name came into existence with the LINK; content, versions and attrs are shared
                        f.firstSeen = n->linkSeen;
                        std::set<TimePoint> own{n->linkSeen};
                        own.insert(f.observations.lower_bound(n->linkSeen), f.observations.end());
                        f.observations = std::move(own);
                    }
                    f.createdInCapture = n->createdInCapture;
                    f.placements.clear();
                    f.setFilename(displayName);
                    f.setFiletype("nfs");
                    f.setOffsetType("tcp");
                    f.setProperty(prop::protocol, "nfs");
                    f.setProperty(prop::srcIP, s.srcIP);
                    f.setProperty(prop::dstIP, s.dstIP);
                    f.setProperty(prop::srcPort, s.srcPort);
                    f.setProperty(prop::dstPort, s.dstPort);
                    f.flags.set(pcapfs::flags::PROCESSED);
                    f.flags.set(pcapfs::flags::IS_SERVERFILE);
                    f.isDirectory = (n->type == NF4DIR) || !n->children.empty() || !n->removedChildren.empty();
                    if (n->type == NF4LNK && !n->linkTarget.empty())
                        f.setProperty("link_target", n->linkTarget);
                    f.deleted = n->deletedAt.has_value();
                    f.deletedAt = n->deletedAt ? *n->deletedAt : TimePoint{};
                    if (s.skew)
                        f.skew = *s.skew;
                    if (f.getClientIPs().empty())
                        f.setClientIPs(s.clients);
                    f.mergeIdenticalVersions();
                    f.flags.reset(pcapfs::flags::IS_METADATA);
                    if (f.isDirectory || n->type == NF4LNK || f.versions.empty())
                        f.flags.set(pcapfs::flags::IS_METADATA);
                    if (f.isDirectory) {
                        const bool hasContent = std::any_of(f.versions.begin(), f.versions.end(),
                                                            [](const NfsVersion &v) { return v.hasContentEvents; });
                        if (hasContent)
                            LOG_WARNING << "NFS: '" << displayName << "' has children and content, keeping its content versions";
                        else
                            f.versions.clear();
                    }
                    f.selectVersion(f.versions.empty() ? 0 : f.versions.size() - 1);

                    const uint64_t id = newId();
                    f.setIdInIndex(id);
                    if (parent) {
                        f.setParentDir(parent->file);
                        f.setParentDirId(parent->file->getIdInIndex());
                    } else {
                        f.setParentDirId(static_cast<uint64_t>(-1));
                        f.setParentDir(nullptr);
                    }
                    registry[SERVER_FILE_TREE_DUMMY][std::to_string(id)] = n->file;

                    std::set<std::string> used;
                    for (auto &child : n->children) {
                        const std::string name = uniqueName(used, sanitizeName(child.first));
                        used.insert(name);
                        below.push_back({resolve(child.second), n, name, 0});
                    }
                    for (Node *removed : n->removedChildren) {
                        if (removed->dead)
                            continue;
                        std::string name = sanitizeName(removed->name);
                        if (used.count(name)) {
                            unsigned k = 1;
                            std::string candidate = name + "@deleted";
                            while (used.count(candidate))
                                candidate = name + "@deleted" + std::to_string(++k);
                            name = candidate;
                        }
                        used.insert(name);
                        below.push_back({removed, n, name, 0});
                    }
                }
            };

        }
    }
}


void pcapfs::nfs::replayStreams(std::vector<ReplayStream> &streams, ServerFileRegistry &registry,
                                const std::function<uint64_t()> &newId) {
    std::vector<Transaction> transactions;
    for (size_t si = 0; si < streams.size(); ++si) {
        for (const NfsMessage &m : streams[si].stream.messages) {
            if (m.isCall && m.isNfs4 && !m.retransmission && m.args)
                transactions.push_back({m.record.time, si, m.index});
        }
    }
    std::sort(transactions.begin(), transactions.end(), [](const Transaction &a, const Transaction &b) {
        return std::tie(a.time, a.stream, a.index) < std::tie(b.time, b.stream, b.index);
    });

    Replayer replayer(streams);
    for (const ReplayStream &ps : streams)
        replayer.stateFor(ps);
    replayer.run(transactions);

    for (auto &entry : replayer.states)
        replayer.materialize(entry.second, registry, newId);
    LOG_DEBUG << "NFS: reconstructed files of " << replayer.states.size() << " server(s)";
}


void pcapfs::nfs::NfsManager::extractMappings(const std::vector<FilePtr> &tcpFiles, const Index &idx, bool checkNonDefaultPorts) {
    LOG_TRACE << "begin with extracting nfs mappings";

    std::vector<ReplayStream> streams;
    for (const auto &tcpFile : tcpFiles) {
        tcpFile->fillBuffer(idx);
        const Bytes data = tcpFile->getBuffer();
        if (!isNfsCandidate(tcpFile, data, checkNonDefaultPorts))
            continue;

        ReplayStream ps;
        try {
            ps.stream = parseNfsStream(data.data(), data.size(), tcpFile->connectionBreaks);
            ps.ep = deriveEndpoints(ps.stream, tcpFile);
        } catch (const std::exception &e) {
            LOG_WARNING << "NFS: skipping a TCP stream that could not be parsed: " << e.what();
            continue;
        }
        ps.tcpId = tcpFile->getIdInIndex();
        ps.srcIP = tcpFile->getProperty(prop::srcIP);
        ps.dstIP = tcpFile->getProperty(prop::dstIP);
        ps.srcPort = tcpFile->getProperty(prop::srcPort);
        ps.dstPort = tcpFile->getProperty(prop::dstPort);
        if (!ps.ep.valid)
            continue;
        const bool onlyCallbacks = std::all_of(ps.stream.messages.begin(), ps.stream.messages.end(),
                                               [](const NfsMessage &m) { return m.isCallback; });
        if (onlyCallbacks)
            continue;
        releasePayloads(ps.stream);

        const size_t numElements = tcpFile->connectionBreaks.size();
        if (numElements > 0) {
            oldestNetworkTimestamp = std::min(oldestNetworkTimestamp, tcpFile->connectionBreaks.at(0).second);
            newestNetworkTimestamp = std::max(newestNetworkTimestamp, tcpFile->connectionBreaks.at(numElements - 1).second);
        }
        streams.push_back(std::move(ps));
    }
    if (streams.empty())
        return;

    replayStreams(streams, serverFiles, [this]() { return getNewId(); });
}


std::vector<pcapfs::FilePtr> const pcapfs::nfs::NfsManager::getServerFiles(const Index &idx) {
    std::vector<FilePtr> resultVector;
    LOG_DEBUG << "Collecting all NFS files...";
    for (const auto &tree : serverFiles) {
        for (auto &fileEntry : tree.second) {
            NfsFilePtr nfsFilePtr = std::static_pointer_cast<NfsFile>(fileEntry.second);
            nfsFilePtr->deduplicateVersions(idx);
            nfsFilePtr->selectVersion(nfsFilePtr->versions.empty() ? 0 : nfsFilePtr->versions.size() - 1);
            nfsFilePtr->updateTimestamps();
            resultVector.push_back(fileEntry.second);
        }
    }
    return resultVector;
}


pcapfs::ServerFilePtr const pcapfs::nfs::NfsManager::getAsParentDirFile(const std::string &filePath, const ServerFileContextPtr &context) {
    (void)context;
    const auto tree = serverFiles.find(SERVER_FILE_TREE_DUMMY);
    if (tree != serverFiles.end()) {
        const auto it = tree->second.find(filePath);
        if (it != tree->second.end())
            return it->second;
    }
    return nullptr;
}


void pcapfs::nfs::NfsManager::adjustServerFilesForDirLayout(std::vector<FilePtr> &indexFiles, TimePoint &snapshot, uint8_t timestampMode) {
    std::vector<pcapfs::FilePtr> filesToAdd;

    (void) snapshot;
    (void) timestampMode;

    LOG_DEBUG << "preparing nfs files for dir layout";
    // placements refer to parent directories by idInIndex
    std::map<uint64_t, FilePtr> filesById;
    if (options::SNAPSHOT_SPECIFIED) {
        for (const FilePtr &f : indexFiles) {
            if (f->isFiletype("nfs"))
                filesById[f->getIdInIndex()] = f;
        }
    }
    std::vector<FilePtr> keep;
    keep.reserve(indexFiles.size());
    for (FilePtr &currFile : indexFiles) {
        if (!currFile->isFiletype("nfs")) {
            keep.push_back(std::move(currFile));
            continue;
        }

        NfsFilePtr nfsFilePtr = std::static_pointer_cast<NfsFile>(currFile);
        if (options::SNAPSHOT_SPECIFIED)
            nfsFilePtr->setPlacementMap(&filesById);
        if (!nfsFilePtr->processFileForDirLayout()) {
            // metadata files are kept as they are, but sit at the place they had at the snapshot time
            if (options::SNAPSHOT_SPECIFIED) {
                nfsFilePtr->applyPlacementAtSnapshot(filesById);
                nfsFilePtr->setPlacementMap(nullptr);
            }
            keep.push_back(std::move(currFile));
            continue;
        }

        if (options::SNAPSHOT_SPECIFIED) {
            const bool keepFile = nfsFilePtr->constructSnapshotFile();
            nfsFilePtr->setPlacementMap(nullptr);   // filesById goes out of scope
            if (keepFile)
                keep.push_back(std::move(currFile));
            // else: no file version fits the snapshot time -> drop
        } else {
            const std::vector<pcapfs::FilePtr> versionFiles = nfsFilePtr->constructVersionFiles();
            if (versionFiles.empty())
                keep.push_back(std::move(currFile));
            else
                filesToAdd.insert(filesToAdd.end(), versionFiles.begin(), versionFiles.end());
        }
    }
    if (options::SNAPSHOT_SPECIFIED)
        resolveSnapshotNames(keep, filesById);
    keep.insert(keep.end(), filesToAdd.begin(), filesToAdd.end());
    indexFiles = std::move(keep);
}


// snapshot mode, after every placement is applied: breaks parent cycles that independent placement choices can
// form (falling back to the final placement) and gives clashing names within a directory the -k suffix of decorate
void pcapfs::nfs::NfsManager::resolveSnapshotNames(std::vector<FilePtr> &files, const std::map<uint64_t, FilePtr> &byId) {
    constexpr size_t MAX_STEPS = 100000;
    std::vector<NfsFile*> nfsFiles;
    for (const FilePtr &f : files) {
        if (f->isFiletype("nfs"))
            nfsFiles.push_back(static_cast<NfsFile*>(f.get()));
    }

    // parent cycles: reset every member of a cycle to its final placement
    for (int round = 0; round < 8; ++round) {
        bool changed = false;
        for (NfsFile *start : nfsFiles) {
            std::vector<uint64_t> chain;
            std::set<uint64_t> visited;
            NfsFile *curr = start;
            size_t steps = 0;
            bool cycle = false;
            while (curr) {
                const uint64_t id = curr->getIdInIndex();
                if (!visited.insert(id).second) {
                    cycle = true;
                    chain.erase(chain.begin(), std::find(chain.begin(), chain.end(), id));
                    break;
                }
                chain.push_back(id);
                if (++steps > MAX_STEPS) {
                    cycle = true;
                    break;
                }
                const auto parent = byId.find(curr->getParentDirId());
                if (!curr->getParentDir() || parent == byId.end() || parent->second->getIdInIndex() == id)
                    break;
                curr = static_cast<NfsFile*>(parent->second.get());
            }
            if (!cycle)
                continue;
            LOG_DEBUG << "NFS: placement cycle at snapshot, using the final placements";
            for (uint64_t id : chain) {
                const auto it = byId.find(id);
                if (it != byId.end())
                    static_cast<NfsFile*>(it->second.get())->applyFinalPlacement(byId);
            }
            changed = true;
        }
        if (!changed)
            break;
    }

    // name clashes: the file with the earliest first placement keeps the plain name
    std::map<std::pair<uint64_t, std::string>, std::vector<NfsFile*>> groups;
    std::set<std::pair<uint64_t, std::string>> used;
    for (NfsFile *f : nfsFiles) {
        groups[{f->getParentDirId(), f->getFilename()}].push_back(f);
        used.insert({f->getParentDirId(), f->getFilename()});
    }
    for (auto &g : groups) {
        if (g.second.size() < 2)
            continue;
        auto first = [](NfsFile *f) { return f->placements.empty() ? f->firstSeen : f->placements.front().since; };
        std::stable_sort(g.second.begin(), g.second.end(), [&](NfsFile *a, NfsFile *b) {
            const TimePoint ta = first(a), tb = first(b);
            return ta != tb ? ta < tb : a->getIdInIndex() < b->getIdInIndex();
        });
        unsigned k = 1;
        for (size_t i = 1; i < g.second.size(); ++i) {
            std::string name;
            do {
                name = g.first.second + "-" + std::to_string(++k);
            } while (used.count({g.first.first, name}));
            used.insert({g.first.first, name});
            g.second[i]->setFilename(name);
        }
    }
}


void pcapfs::nfs::NfsManager::serialize(boost::archive::text_oarchive &archive, const unsigned int&) {
    archive << oldestNetworkTimestamp;
    archive << newestNetworkTimestamp;
}


void pcapfs::nfs::NfsManager::deserialize(boost::archive::text_iarchive &archive, const unsigned int&) {
    archive >> oldestNetworkTimestamp;
    archive >> newestNetworkTimestamp;
}
