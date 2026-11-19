#include "nfscontrol.h"
#include "nfs/nfs_stream.h"
#include "../filefactory.h"
#include "../config.h"
#include "../properties.h"
#include "../logging.h"
#include "../exceptions.h"
#include <algorithm>
#include <cstring>


std::vector<pcapfs::FilePtr> pcapfs::NfsControlFile::parse(FilePtr filePtr, Index &idx) {
    (void)idx;
    std::vector<pcapfs::FilePtr> resultVector;
    try {
        if (!filePtr || filePtr->getProperty(prop::protocol) != "tcp" || filePtr->connectionBreaks.empty())
            return resultVector;
        const Bytes data = filePtr->getBuffer();
        if (!nfs::isNfsCandidate(filePtr, data, config.checkNonDefaultPorts))
            return resultVector;

        LOG_TRACE << "detected NFS traffic and start parsing";
        const nfs::NfsStream stream = nfs::parseNfsStream(data.data(), data.size(), filePtr->connectionBreaks);
        const std::string text = nfs::renderControlText(stream);

        std::shared_ptr<NfsControlFile> controlFilePtr = std::make_shared<NfsControlFile>();
        controlFilePtr->setTimestamp(filePtr->connectionBreaks.at(0).second);
        controlFilePtr->setProperty(prop::protocol, "nfs");
        controlFilePtr->setFiletype("nfscontrol");
        controlFilePtr->setOffsetType(filePtr->getFiletype());
        controlFilePtr->setProperty(prop::srcIP, filePtr->getProperty(prop::srcIP));
        controlFilePtr->setProperty(prop::dstIP, filePtr->getProperty(prop::dstIP));
        controlFilePtr->setProperty(prop::srcPort, filePtr->getProperty(prop::srcPort));
        controlFilePtr->setProperty(prop::dstPort, filePtr->getProperty(prop::dstPort));
        controlFilePtr->setFilename("NFS.control");
        controlFilePtr->flags.set(pcapfs::flags::IS_METADATA);
        controlFilePtr->tcpBreaks = filePtr->connectionBreaks;

        Fragment fragment;
        fragment.id = filePtr->getIdInIndex();
        fragment.start = 0;
        fragment.length = filePtr->getFilesizeProcessed();
        controlFilePtr->fragments.push_back(fragment);

        controlFilePtr->flags.set(pcapfs::flags::PROCESSED);
        controlFilePtr->setFilesizeRaw(text.size());
        controlFilePtr->setFilesizeProcessed(text.size());

        resultVector.push_back(controlFilePtr);
        return resultVector;
    } catch (const std::exception &e) {
        LOG_WARNING << "NFS control file: parsing failed: " << e.what();
    }
    return {};
}


size_t pcapfs::NfsControlFile::read(uint64_t startOffset, size_t length, const Index &idx, char *buf) {
    try {
        if (fragments.empty())
            return 0;
        const FilePtr filePtr = idx.get({offsetType, fragments.at(0).id});
        if (!filePtr)
            return 0;
        Bytes data(filePtr->getFilesizeProcessed());
        filePtr->read(0, data.size(), idx, reinterpret_cast<char *>(data.data()));
        const nfs::NfsStream stream = nfs::parseNfsStream(data.data(), data.size(), tcpBreaks);
        const std::string text = nfs::renderControlText(stream);

        if (startOffset >= text.size())
            return 0;
        const size_t toRead = std::min<size_t>(text.size() - startOffset, length);
        memcpy(buf, text.data() + startOffset, toRead);
        return toRead;
    } catch (const std::exception &e) {
        LOG_WARNING << "NFS control file: reading failed: " << e.what();
    }
    return 0;
}


void pcapfs::NfsControlFile::serialize(boost::archive::text_oarchive &archive) {
    VirtualFile::serialize(archive);
    archive << tcpBreaks;
}


void pcapfs::NfsControlFile::deserialize(boost::archive::text_iarchive &archive) {
    VirtualFile::deserialize(archive);
    archive >> tcpBreaks;
}


bool pcapfs::NfsControlFile::registeredAtFactory =
        pcapfs::FileFactory::registerAtFactory("nfscontrol", pcapfs::NfsControlFile::create, pcapfs::NfsControlFile::parse);
