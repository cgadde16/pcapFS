#ifndef PCAPFS_VIRTUAL_FILES_NFSCONTROL_H
#define PCAPFS_VIRTUAL_FILES_NFSCONTROL_H

#include "virtualfile.h"

#include <vector>

#include <boost/serialization/utility.hpp>
#include <boost/serialization/vector.hpp>

namespace pcapfs {

    class NfsControlFile : public VirtualFile {
    public:
        static FilePtr create() { return std::make_shared<NfsControlFile>(); };

        static std::vector<FilePtr> parse(FilePtr filePtr, Index &idx);
        size_t read(uint64_t startOffset, size_t length, const Index &idx, char *buf) override;

        void serialize(boost::archive::text_oarchive &archive) override;
        void deserialize(boost::archive::text_iarchive &archive) override;

        // copy of the TCP file's connectionBreaks (TcpFile does not serialize them); read() needs them when mounted
        // from an index
        std::vector<FragmentWithTime> tcpBreaks;

    protected:
        static bool registeredAtFactory;
    };
}

#endif //PCAPFS_VIRTUAL_FILES_NFSCONTROL_H
