#ifndef PCAPFS_NFS_MANAGER_H
#define PCAPFS_NFS_MANAGER_H

#include "../serverfile_manager.h"
#include "../nfs.h"
#include "nfs_stream.h"

#include <algorithm>
#include <functional>
#include <map>

namespace pcapfs {
    namespace nfs {

        // an already parsed NFS TCP stream together with the endpoint info the replay needs
        struct ReplayStream {
            uint64_t tcpId = 0;
            std::string srcIP, dstIP, srcPort, dstPort;
            NfsStream stream;
            NfsEndpoints ep;
        };

        using ServerFileRegistry = std::map<ServerFileTree, std::map<std::string, ServerFilePtr>>;

        // replays the NFSv4 COMPOUNDs of the streams chronologically and registers the resulting files
        // (called by extractMappings)
        void replayStreams(std::vector<ReplayStream> &streams, ServerFileRegistry &registry, const std::function<uint64_t()> &newId);

        class NfsManager : public ServerFileManager {
        public:
            static NfsManager& getInstance() {
                static NfsManager instance;
                return instance;
            }

            NfsManager(NfsManager const&) = delete;
            void operator=(NfsManager const&) = delete;

            // parses all NFS candidate TCP streams, replays the NFSv4 COMPOUNDs chronologically and builds the NfsFiles
            void extractMappings(const std::vector<FilePtr> &tcpFiles, const Index &idx, bool checkNonDefaultPorts);

            std::vector<FilePtr> const getServerFiles(const Index &idx) override;
            ServerFilePtr const getAsParentDirFile(const std::string &filePath, const ServerFileContextPtr &context) override;
            void adjustServerFilesForDirLayout(std::vector<FilePtr> &indexFiles, TimePoint &snapshot, uint8_t timestampMode) override;
            // widens [oldest, newest] to include the network time range of the NFS traffic (no change without traffic)
            void extendNetworkTimeRange(TimePoint &oldest, TimePoint &newest) const {
                oldest = std::min(oldest, oldestNetworkTimestamp);
                newest = std::max(newest, newestNetworkTimestamp);
            }
            // snapshot mode: breaks placement parent cycles and dedupes names per directory (see the definition)
            static void resolveSnapshotNames(std::vector<FilePtr> &files, const std::map<uint64_t, FilePtr> &byId);

            void serialize(boost::archive::text_oarchive &archive, const unsigned int&);
            void deserialize(boost::archive::text_iarchive &archive, const unsigned int&);

        private:
            NfsManager() {
                // id 0 means "assign one" for Index::insert
                getNewId();
            }

            // first connectionBreak
            TimePoint oldestNetworkTimestamp = TimePoint::max();
            // last connectionBreak
            TimePoint newestNetworkTimestamp = TimePoint{};
        };
    }
}

#endif // PCAPFS_NFS_MANAGER_H
