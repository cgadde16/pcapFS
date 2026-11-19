#ifndef PCAPFS_NFS_NFS4_OPS_H
#define PCAPFS_NFS_NFS4_OPS_H

#include <cstdint>
#include <optional>
#include <string>
#include <variant>
#include <vector>

#include "nfs4_attrs.h"
#include "xdr.h"

// NFSv4.0/4.1/4.2 COMPOUND and CB_COMPOUND decoding (nfs4_prot.x, RFC 7863; RFC 8276 for xattr operations)
// all Span members are relative to the buffer of the XdrDecoder that was passed in
namespace pcapfs {
    namespace nfs {

        namespace op {
            constexpr uint32_t ACCESS = 3, CLOSE = 4, COMMIT = 5, CREATE = 6, DELEGPURGE = 7, DELEGRETURN = 8,
                    GETATTR = 9, GETFH = 10, LINK = 11, LOCK = 12, LOCKT = 13, LOCKU = 14, LOOKUP = 15,
                    LOOKUPP = 16, NVERIFY = 17, OPEN = 18, OPENATTR = 19, OPEN_CONFIRM = 20, OPEN_DOWNGRADE = 21,
                    PUTFH = 22, PUTPUBFH = 23, PUTROOTFH = 24, READ = 25, READDIR = 26, READLINK = 27,
                    REMOVE = 28, RENAME = 29, RENEW = 30, RESTOREFH = 31, SAVEFH = 32, SECINFO = 33,
                    SETATTR = 34, SETCLIENTID = 35, SETCLIENTID_CONFIRM = 36, VERIFY = 37, WRITE = 38,
                    RELEASE_LOCKOWNER = 39, BACKCHANNEL_CTL = 40, BIND_CONN_TO_SESSION = 41, EXCHANGE_ID = 42,
                    CREATE_SESSION = 43, DESTROY_SESSION = 44, FREE_STATEID = 45, GET_DIR_DELEGATION = 46,
                    GETDEVICEINFO = 47, GETDEVICELIST = 48, LAYOUTCOMMIT = 49, LAYOUTGET = 50,
                    LAYOUTRETURN = 51, SECINFO_NO_NAME = 52, SEQUENCE = 53, SET_SSV = 54, TEST_STATEID = 55,
                    WANT_DELEGATION = 56, DESTROY_CLIENTID = 57, RECLAIM_COMPLETE = 58, ALLOCATE = 59,
                    COPY = 60, COPY_NOTIFY = 61, DEALLOCATE = 62, IO_ADVISE = 63, LAYOUTERROR = 64,
                    LAYOUTSTATS = 65, OFFLOAD_CANCEL = 66, OFFLOAD_STATUS = 67, READ_PLUS = 68, SEEK = 69,
                    WRITE_SAME = 70, CLONE = 71, GETXATTR = 72, SETXATTR = 73, LISTXATTRS = 74,
                    REMOVEXATTR = 75, ILLEGAL = 10044;
            constexpr uint32_t CB_GETATTR = 3, CB_RECALL = 4, CB_LAYOUTRECALL = 5, CB_NOTIFY = 6,
                    CB_PUSH_DELEG = 7, CB_RECALL_ANY = 8, CB_RECALLABLE_OBJ_AVAIL = 9, CB_RECALL_SLOT = 10,
                    CB_SEQUENCE = 11, CB_WANTS_CANCELLED = 12, CB_NOTIFY_LOCK = 13, CB_NOTIFY_DEVICEID = 14,
                    CB_OFFLOAD = 15, CB_ILLEGAL = 10044;
        }

        constexpr uint32_t NFS4_OK = 0;
        constexpr uint32_t NFS4ERR_DENIED = 10010;
        constexpr uint32_t NFS4ERR_CLID_INUSE = 10017;
        constexpr uint32_t NFS4ERR_TOOSMALL = 10005;
        constexpr uint32_t NFS4ERR_LAYOUTTRYLATER = 10058;
        constexpr uint32_t NFS4ERR_OFFLOAD_NO_REQS = 10094;

        // nfs_ftype4
        constexpr uint32_t NF4REG = 1, NF4DIR = 2, NF4BLK = 3, NF4CHR = 4, NF4LNK = 5;
        // opentype4
        constexpr uint32_t OPEN4_NOCREATE = 0, OPEN4_CREATE = 1;
        // createmode4
        constexpr uint32_t UNCHECKED4 = 0, GUARDED4 = 1, EXCLUSIVE4 = 2, EXCLUSIVE4_1 = 3;
        // open_claim_type4 (deleg_claim4 uses the same numbers)
        constexpr uint32_t CLAIM_NULL = 0, CLAIM_PREVIOUS = 1, CLAIM_DELEGATE_CUR = 2, CLAIM_DELEGATE_PREV = 3,
                           CLAIM_FH = 4, CLAIM_DELEG_CUR_FH = 5, CLAIM_DELEG_PREV_FH = 6;
        // data_content4
        constexpr uint32_t NFS4_CONTENT_DATA = 0, NFS4_CONTENT_HOLE = 1;

        const char *opName(uint32_t opnum);     // "PUTFH", ..., "ILLEGAL"; "UNKNOWN" otherwise
        const char *cbOpName(uint32_t opnum);
        const char *nfsstat4Name(uint32_t stat); // "NFS4_OK", "NFS4ERR_NOENT", ...; "NFS4ERR_UNKNOWN" otherwise

        struct GenericArgs {};          // operations whose arguments are not kept

        struct PutfhArgs { Nfsfh4 fh; };
        struct NameArgs { std::string name; };  // LOOKUP, REMOVE, LINK, SECINFO, GETXATTR, REMOVEXATTR
        struct OpenArgs {
            uint32_t openType = 0;              // opentype4
            uint32_t createMode = 0;            // createmode4, if openType creates
            std::optional<Fattr4> createAttrs;  // UNCHECKED4, GUARDED4, EXCLUSIVE4_1
            uint32_t claimType = 0;             // open_claim_type4
            std::string file;                   // CLAIM_NULL, CLAIM_DELEGATE_CUR, CLAIM_DELEGATE_PREV
        };
        struct ReadArgs { uint64_t offset = 0; uint32_t count = 0; }; // READ, READ_PLUS
        struct WriteArgs { uint64_t offset = 0; Span data{0, 0}; };
        struct RangeArgs { uint64_t offset = 0; uint64_t length = 0; }; // ALLOCATE, DEALLOCATE
        struct CopyArgs {
            uint64_t srcOffset = 0;
            uint64_t dstOffset = 0;
            uint64_t count = 0;
        };
        struct CloneArgs {
            uint64_t srcOffset = 0;
            uint64_t dstOffset = 0;
            uint64_t count = 0;
        };
        struct SetattrArgs { Fattr4 attrs; };
        struct CreateArgs {
            uint32_t objType = 0;               // nfs_ftype4
            std::string linkdata;               // NF4LNK
            std::string name;
            Fattr4 attrs;
        };
        struct RenameArgs { std::string oldname; std::string newname; };

        using ArgVariant = std::variant<GenericArgs, PutfhArgs, NameArgs, OpenArgs, ReadArgs, WriteArgs, RangeArgs,
                CopyArgs, CloneArgs, SetattrArgs, CreateArgs, RenameArgs>;

        struct ArgOp {
            uint32_t op = 0;
            ArgVariant args;
        };

        // result structs (the status is stored in ResOp)

        struct GenericRes {};           // results that are not kept (also any operation with a failure status)

        struct GetattrRes { Fattr4 attrs; };
        struct GetfhRes { Nfsfh4 fh; };
        struct OpenRes {
            ChangeInfo4 cinfo;
        };
        struct ReadRes { Span data{0, 0}; };
        struct DirEntry4 { std::string name; Fattr4 attrs; };
        struct ReaddirRes { std::vector<DirEntry4> entries; };
        struct ReadlinkRes { std::string link; };
        struct WriteRes { uint32_t count = 0; };
        struct CopyRes { uint64_t count = 0; };
        struct ReadPlusContent {
            uint32_t type = 0;                   // 0 DATA, 1 HOLE
            uint64_t offset = 0;
            uint64_t length = 0;                 // HOLE
            Span data{0, 0};                     // DATA
        };
        struct ReadPlusRes { std::vector<ReadPlusContent> contents; };

        using ResVariant = std::variant<GenericRes, GetattrRes, GetfhRes, OpenRes, ReadRes, ReaddirRes, ReadlinkRes,
                WriteRes, CopyRes, ReadPlusRes>;

        struct ResOp {
            uint32_t op = 0;
            uint32_t status = 0;
            ResVariant res;
        };

        // a COMPOUND with more operations than this is decoded only up to the limit and marked as failed
        constexpr uint32_t MAX_COMPOUND_OPS = 1024;

        struct CompoundArgs {
            std::vector<ArgOp> ops;
            bool complete = false;
        };

        struct CompoundRes {
            uint32_t status = 0;
            std::vector<ResOp> ops;
            bool complete = false;
        };

        // decoders never throw; truncation or an unknown opcode yields complete=false and the
        // operations decoded so far; the decoder is expected to be positioned at the COMPOUND body
        CompoundArgs decodeCompoundArgs(XdrDecoder &dec);
        CompoundRes decodeCompoundRes(XdrDecoder &dec);

        // single operation decoders (throw XdrError); used by the compound decoders
        ArgOp decodeArgOp(XdrDecoder &dec);
        ResOp decodeResOp(XdrDecoder &dec);

        using CbArgVariant = std::variant<GenericArgs>;

        struct CbArgOp {
            uint32_t op = 0;
            CbArgVariant args;
        };

        struct CbCompoundArgs {
            std::vector<CbArgOp> ops;
            bool complete = false;
        };

        using CbResVariant = std::variant<GenericRes>;

        struct CbResOp {
            uint32_t op = 0;
            uint32_t status = 0;
            CbResVariant res;
        };

        struct CbCompoundRes {
            uint32_t status = 0;
            std::vector<CbResOp> ops;
            bool complete = false;
        };

        CbCompoundArgs decodeCbCompoundArgs(XdrDecoder &dec);
        CbCompoundRes decodeCbCompoundRes(XdrDecoder &dec);

    }
}

#endif //PCAPFS_NFS_NFS4_OPS_H
