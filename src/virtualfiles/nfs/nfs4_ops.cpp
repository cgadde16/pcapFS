#include "nfs4_ops.h"

namespace pcapfs {
    namespace nfs {

        namespace {
            struct StatusName {
                uint32_t code;
                const char *name;
            };

            const StatusName STATUS_NAMES[] = {
                {0, "NFS4_OK"},
                {1, "NFS4ERR_PERM"},
                {2, "NFS4ERR_NOENT"},
                {5, "NFS4ERR_IO"},
                {6, "NFS4ERR_NXIO"},
                {13, "NFS4ERR_ACCESS"},
                {17, "NFS4ERR_EXIST"},
                {18, "NFS4ERR_XDEV"},
                {20, "NFS4ERR_NOTDIR"},
                {21, "NFS4ERR_ISDIR"},
                {22, "NFS4ERR_INVAL"},
                {27, "NFS4ERR_FBIG"},
                {28, "NFS4ERR_NOSPC"},
                {30, "NFS4ERR_ROFS"},
                {31, "NFS4ERR_MLINK"},
                {63, "NFS4ERR_NAMETOOLONG"},
                {66, "NFS4ERR_NOTEMPTY"},
                {69, "NFS4ERR_DQUOT"},
                {70, "NFS4ERR_STALE"},
                {10001, "NFS4ERR_BADHANDLE"},
                {10003, "NFS4ERR_BAD_COOKIE"},
                {10004, "NFS4ERR_NOTSUPP"},
                {10005, "NFS4ERR_TOOSMALL"},
                {10006, "NFS4ERR_SERVERFAULT"},
                {10007, "NFS4ERR_BADTYPE"},
                {10008, "NFS4ERR_DELAY"},
                {10009, "NFS4ERR_SAME"},
                {10010, "NFS4ERR_DENIED"},
                {10011, "NFS4ERR_EXPIRED"},
                {10012, "NFS4ERR_LOCKED"},
                {10013, "NFS4ERR_GRACE"},
                {10014, "NFS4ERR_FHEXPIRED"},
                {10015, "NFS4ERR_SHARE_DENIED"},
                {10016, "NFS4ERR_WRONGSEC"},
                {10017, "NFS4ERR_CLID_INUSE"},
                {10018, "NFS4ERR_RESOURCE"},
                {10019, "NFS4ERR_MOVED"},
                {10020, "NFS4ERR_NOFILEHANDLE"},
                {10021, "NFS4ERR_MINOR_VERS_MISMATCH"},
                {10022, "NFS4ERR_STALE_CLIENTID"},
                {10023, "NFS4ERR_STALE_STATEID"},
                {10024, "NFS4ERR_OLD_STATEID"},
                {10025, "NFS4ERR_BAD_STATEID"},
                {10026, "NFS4ERR_BAD_SEQID"},
                {10027, "NFS4ERR_NOT_SAME"},
                {10028, "NFS4ERR_LOCK_RANGE"},
                {10029, "NFS4ERR_SYMLINK"},
                {10030, "NFS4ERR_RESTOREFH"},
                {10031, "NFS4ERR_LEASE_MOVED"},
                {10032, "NFS4ERR_ATTRNOTSUPP"},
                {10033, "NFS4ERR_NO_GRACE"},
                {10034, "NFS4ERR_RECLAIM_BAD"},
                {10035, "NFS4ERR_RECLAIM_CONFLICT"},
                {10036, "NFS4ERR_BADXDR"},
                {10037, "NFS4ERR_LOCKS_HELD"},
                {10038, "NFS4ERR_OPENMODE"},
                {10039, "NFS4ERR_BADOWNER"},
                {10040, "NFS4ERR_BADCHAR"},
                {10041, "NFS4ERR_BADNAME"},
                {10042, "NFS4ERR_BAD_RANGE"},
                {10043, "NFS4ERR_LOCK_NOTSUPP"},
                {10044, "NFS4ERR_OP_ILLEGAL"},
                {10045, "NFS4ERR_DEADLOCK"},
                {10046, "NFS4ERR_FILE_OPEN"},
                {10047, "NFS4ERR_ADMIN_REVOKED"},
                {10048, "NFS4ERR_CB_PATH_DOWN"},
                {10049, "NFS4ERR_BADIOMODE"},
                {10050, "NFS4ERR_BADLAYOUT"},
                {10051, "NFS4ERR_BAD_SESSION_DIGEST"},
                {10052, "NFS4ERR_BADSESSION"},
                {10053, "NFS4ERR_BADSLOT"},
                {10054, "NFS4ERR_COMPLETE_ALREADY"},
                {10055, "NFS4ERR_CONN_NOT_BOUND_TO_SESSION"},
                {10056, "NFS4ERR_DELEG_ALREADY_WANTED"},
                {10057, "NFS4ERR_BACK_CHAN_BUSY"},
                {10058, "NFS4ERR_LAYOUTTRYLATER"},
                {10059, "NFS4ERR_LAYOUTUNAVAILABLE"},
                {10060, "NFS4ERR_NOMATCHING_LAYOUT"},
                {10061, "NFS4ERR_RECALLCONFLICT"},
                {10062, "NFS4ERR_UNKNOWN_LAYOUTTYPE"},
                {10063, "NFS4ERR_SEQ_MISORDERED"},
                {10064, "NFS4ERR_SEQUENCE_POS"},
                {10065, "NFS4ERR_REQ_TOO_BIG"},
                {10066, "NFS4ERR_REP_TOO_BIG"},
                {10067, "NFS4ERR_REP_TOO_BIG_TO_CACHE"},
                {10068, "NFS4ERR_RETRY_UNCACHED_REP"},
                {10069, "NFS4ERR_UNSAFE_COMPOUND"},
                {10070, "NFS4ERR_TOO_MANY_OPS"},
                {10071, "NFS4ERR_OP_NOT_IN_SESSION"},
                {10072, "NFS4ERR_HASH_ALG_UNSUPP"},
                {10074, "NFS4ERR_CLIENTID_BUSY"},
                {10075, "NFS4ERR_PNFS_IO_HOLE"},
                {10076, "NFS4ERR_SEQ_FALSE_RETRY"},
                {10077, "NFS4ERR_BAD_HIGH_SLOT"},
                {10078, "NFS4ERR_DEADSESSION"},
                {10079, "NFS4ERR_ENCR_ALG_UNSUPP"},
                {10080, "NFS4ERR_PNFS_NO_LAYOUT"},
                {10081, "NFS4ERR_NOT_ONLY_OP"},
                {10082, "NFS4ERR_WRONG_CRED"},
                {10083, "NFS4ERR_WRONG_TYPE"},
                {10084, "NFS4ERR_DIRDELEG_UNAVAIL"},
                {10085, "NFS4ERR_REJECT_DELEG"},
                {10086, "NFS4ERR_RETURNCONFLICT"},
                {10087, "NFS4ERR_DELEG_REVOKED"},
                {10088, "NFS4ERR_PARTNER_NOTSUPP"},
                {10089, "NFS4ERR_PARTNER_NO_AUTH"},
                {10090, "NFS4ERR_UNION_NOTSUPP"},
                {10091, "NFS4ERR_OFFLOAD_DENIED"},
                {10092, "NFS4ERR_WRONG_LFS"},
                {10093, "NFS4ERR_BADLABEL"},
                {10094, "NFS4ERR_OFFLOAD_NO_REQS"},
                {10095, "NFS4ERR_NOXATTR"},
                {10096, "NFS4ERR_XATTR2BIG"},
            };
            const char *const OP_NAMES[] = {
                "ACCESS", // 3
                "CLOSE", // 4
                "COMMIT", // 5
                "CREATE", // 6
                "DELEGPURGE", // 7
                "DELEGRETURN", // 8
                "GETATTR", // 9
                "GETFH", // 10
                "LINK", // 11
                "LOCK", // 12
                "LOCKT", // 13
                "LOCKU", // 14
                "LOOKUP", // 15
                "LOOKUPP", // 16
                "NVERIFY", // 17
                "OPEN", // 18
                "OPENATTR", // 19
                "OPEN_CONFIRM", // 20
                "OPEN_DOWNGRADE", // 21
                "PUTFH", // 22
                "PUTPUBFH", // 23
                "PUTROOTFH", // 24
                "READ", // 25
                "READDIR", // 26
                "READLINK", // 27
                "REMOVE", // 28
                "RENAME", // 29
                "RENEW", // 30
                "RESTOREFH", // 31
                "SAVEFH", // 32
                "SECINFO", // 33
                "SETATTR", // 34
                "SETCLIENTID", // 35
                "SETCLIENTID_CONFIRM", // 36
                "VERIFY", // 37
                "WRITE", // 38
                "RELEASE_LOCKOWNER", // 39
                "BACKCHANNEL_CTL", // 40
                "BIND_CONN_TO_SESSION", // 41
                "EXCHANGE_ID", // 42
                "CREATE_SESSION", // 43
                "DESTROY_SESSION", // 44
                "FREE_STATEID", // 45
                "GET_DIR_DELEGATION", // 46
                "GETDEVICEINFO", // 47
                "GETDEVICELIST", // 48
                "LAYOUTCOMMIT", // 49
                "LAYOUTGET", // 50
                "LAYOUTRETURN", // 51
                "SECINFO_NO_NAME", // 52
                "SEQUENCE", // 53
                "SET_SSV", // 54
                "TEST_STATEID", // 55
                "WANT_DELEGATION", // 56
                "DESTROY_CLIENTID", // 57
                "RECLAIM_COMPLETE", // 58
                "ALLOCATE", // 59
                "COPY", // 60
                "COPY_NOTIFY", // 61
                "DEALLOCATE", // 62
                "IO_ADVISE", // 63
                "LAYOUTERROR", // 64
                "LAYOUTSTATS", // 65
                "OFFLOAD_CANCEL", // 66
                "OFFLOAD_STATUS", // 67
                "READ_PLUS", // 68
                "SEEK", // 69
                "WRITE_SAME", // 70
                "CLONE", // 71
                "GETXATTR", "SETXATTR", "LISTXATTRS", "REMOVEXATTR" // 72..75
            };
            const char *const CB_OP_NAMES[] = {
                "CB_GETATTR", // 3
                "CB_RECALL", // 4
                "CB_LAYOUTRECALL", // 5
                "CB_NOTIFY", // 6
                "CB_PUSH_DELEG", // 7
                "CB_RECALL_ANY", // 8
                "CB_RECALLABLE_OBJ_AVAIL", // 9
                "CB_RECALL_SLOT", // 10
                "CB_SEQUENCE", // 11
                "CB_WANTS_CANCELLED", // 12
                "CB_NOTIFY_LOCK", // 13
                "CB_NOTIFY_DEVICEID", // 14
                "CB_OFFLOAD", // 15
            };

            template <typename F>
            auto vec(XdrDecoder &d, size_t minElem, F f) {
                std::vector<decltype(f(d))> v;
                for (uint32_t n = d.arrayCount(minElem); n > 0; --n)
                    v.push_back(f(d));
                return v;
            }

            template <typename F>
            void repeat(XdrDecoder &d, size_t minElem, F f) {
                for (uint32_t n = d.arrayCount(minElem); n > 0; --n)
                    f(d);
            }

            [[noreturn]] void bad(const char *what, uint32_t v) {
                throw XdrError(std::string("invalid ") + what + " " + std::to_string(v));
            }

            void stateOwner(XdrDecoder &d) {
                d.u64();
                d.string();
            }

            void netAddr(XdrDecoder &d) {
                d.string();
                d.string();
            }

            void netloc(XdrDecoder &d) {
                const uint32_t type = d.u32();
                switch (type) {
                    case 1: case 2: d.string(); break;
                    case 3: netAddr(d); break;
                    default: bad("netloc4 type", type);
                }
            }

            void ace(XdrDecoder &d) {
                d.u32();
                d.u32();
                d.u32();
                d.string();
            }

            uint64_t writeResponse(XdrDecoder &d) {
                repeat(d, 16, skipStateid4);
                const uint64_t count = d.u64();
                d.u32();
                decodeVerifier4(d);
                return count;
            }

            void copyReqs(XdrDecoder &d) {
                d.boolean();
                d.boolean();
            }

            void lockDenied(XdrDecoder &d) {
                d.u64();
                d.u64();
                d.u32();
                stateOwner(d);
            }

            void openDelegation(XdrDecoder &d) {
                const uint32_t type = d.u32();
                switch (type) {
                    case 0:
                        break;
                    case 1:
                    case 4:  // OPEN_DELEGATE_READ_ATTRS_DELEG (attribute delegations, same layout as read)
                        skipStateid4(d);
                        d.boolean();
                        ace(d);
                        break;
                    case 2:
                    case 5: {  // OPEN_DELEGATE_WRITE_ATTRS_DELEG (same layout as write)
                        skipStateid4(d);
                        d.boolean();
                        const uint32_t limitBy = d.u32();
                        if (limitBy == 1) {
                            d.u64();
                        } else if (limitBy == 2) {
                            d.u32();
                            d.u32();
                        } else {
                            bad("limit_by4", limitBy);
                        }
                        ace(d);
                        break;
                    }
                    case 3: {
                        const uint32_t whyNone = d.u32();
                        if (whyNone == 1 || whyNone == 2)
                            d.boolean();
                        break;
                    }
                    default:
                        bad("open_delegation_type4", type);
                }
            }

            void protectOps(XdrDecoder &d) {
                decodeBitmap4(d);
                decodeBitmap4(d);
            }

            void skipString(XdrDecoder &d) { d.string(); }

            void protectArgs(XdrDecoder &d) {
                const uint32_t how = d.u32();
                switch (how) {
                    case 0: break;
                    case 1: protectOps(d); break;
                    case 2:
                        protectOps(d);
                        repeat(d, 4, skipString);
                        repeat(d, 4, skipString);
                        d.u32();
                        d.u32();
                        break;
                    default: bad("state_protect_how4", how);
                }
            }

            void protectRes(XdrDecoder &d) {
                const uint32_t how = d.u32();
                switch (how) {
                    case 0: break;
                    case 1: protectOps(d); break;
                    case 2:
                        protectOps(d);
                        d.u32();
                        d.u32();
                        d.u32();
                        d.u32();
                        repeat(d, 4, skipString);
                        break;
                    default: bad("state_protect_how4", how);
                }
            }

            void implId(XdrDecoder &d) {
                d.string();
                d.string();
                decodeNfstime4(d);
            }

            void channelAttrs(XdrDecoder &d) {
                d.u32();
                d.u32();
                d.u32();
                d.u32();
                d.u32();
                d.u32();
                const uint32_t n = d.arrayCount();
                for (uint32_t i = 0; i < n; ++i)
                    d.u32();
            }

            void cbSecParms(XdrDecoder &d) {
                const uint32_t flavor = d.u32();
                switch (flavor) {
                    case 0: break;
                    case 1:
                        d.u32();
                        d.string();
                        d.u32();
                        d.u32();
                        repeat(d, 4, [](XdrDecoder &x) { x.u32(); });
                        break;
                    case 6:
                        d.u32();
                        d.string();
                        d.string();
                        break;
                    default: bad("callback_sec_parms4 flavor", flavor);
                }
            }

            void layoutUpdate(XdrDecoder &d) {
                d.u32();
                d.opaqueVarSpan();
            }

            void ioInfo(XdrDecoder &d) {
                d.u64();
                d.u64();
            }

            void notify(XdrDecoder &d) {
                decodeBitmap4(d);
                d.opaqueVarSpan();
            }

            void decodeOpenArgs(XdrDecoder &d, OpenArgs &o) {
                d.u32();
                d.u32();
                d.u32();
                stateOwner(d);
                o.openType = d.u32();
                if (o.openType == OPEN4_CREATE) {
                    o.createMode = d.u32();
                    switch (o.createMode) {
                        case UNCHECKED4: case GUARDED4:
                            o.createAttrs = decodeFattr4(d);
                            break;
                        case EXCLUSIVE4:
                            decodeVerifier4(d);
                            break;
                        case EXCLUSIVE4_1:
                            decodeVerifier4(d);
                            o.createAttrs = decodeFattr4(d);
                            break;
                        default: bad("createmode4", o.createMode);
                    }
                } else if (o.openType != OPEN4_NOCREATE) {
                    bad("opentype4", o.openType);
                }
                o.claimType = d.u32();
                switch (o.claimType) {
                    case CLAIM_NULL: case CLAIM_DELEGATE_PREV: o.file = d.string(); break;
                    case CLAIM_PREVIOUS: d.u32(); break;
                    case CLAIM_DELEGATE_CUR:
                        skipStateid4(d);
                        o.file = d.string();
                        break;
                    case CLAIM_FH: case CLAIM_DELEG_PREV_FH: break;
                    case CLAIM_DELEG_CUR_FH: skipStateid4(d); break;
                    default: bad("open_claim_type4", o.claimType);
                }
            }

            void decodeLockArgs(XdrDecoder &d) {
                d.u32();
                d.boolean();
                d.u64();
                d.u64();
                const bool newLockOwner = d.boolean();
                if (newLockOwner) {
                    d.u32();
                    skipStateid4(d);
                    d.u32();
                    stateOwner(d);
                } else {
                    skipStateid4(d);
                    d.u32();
                }
            }

            void decodeCopyArgs(XdrDecoder &d, CopyArgs &c) {
                skipStateid4(d);
                skipStateid4(d);
                c.srcOffset = d.u64();
                c.dstOffset = d.u64();
                c.count = d.u64();
                d.boolean();
                d.boolean();
                repeat(d, 8, netloc);
            }

            void decodeLayoutreturnArgs(XdrDecoder &d) {
                d.boolean();
                d.u32();
                d.u32();
                const uint32_t returnType = d.u32();
                if (returnType == 1) {
                    d.u64();
                    d.u64();
                    skipStateid4(d);
                    d.opaqueVarSpan();
                } else if (returnType != 2 && returnType != 3) {
                    bad("layoutreturn_type4", returnType);
                }
            }

            void decodeWriteSameArgs(XdrDecoder &d) {
                skipStateid4(d);
                d.u32();
                d.u64();
                d.u64();
                d.u64();
                d.u64();
                d.u32();
                d.u64();
                d.opaqueVarSpan();
            }
        }

        const char *opName(uint32_t opnum) {
            if (opnum >= 3 && opnum - 3 < sizeof(OP_NAMES) / sizeof(OP_NAMES[0]))
                return OP_NAMES[opnum - 3];
            return opnum == op::ILLEGAL ? "ILLEGAL" : "UNKNOWN";
        }

        const char *cbOpName(uint32_t opnum) {
            if (opnum >= 3 && opnum - 3 < sizeof(CB_OP_NAMES) / sizeof(CB_OP_NAMES[0]))
                return CB_OP_NAMES[opnum - 3];
            return opnum == op::CB_ILLEGAL ? "CB_ILLEGAL" : "CB_UNKNOWN";
        }

        const char *nfsstat4Name(uint32_t stat) {
            for (const StatusName &s : STATUS_NAMES)
                if (s.code == stat)
                    return s.name;
            return "NFS4ERR_UNKNOWN";
        }

        ArgOp decodeArgOp(XdrDecoder &d) {
            ArgOp a;
            a.op = d.u32();
            switch (a.op) {
                case op::ACCESS: d.u32(); break;
                case op::CLOSE:
                d.u32();
                skipStateid4(d);
                break;
                case op::COMMIT:
                d.u64();
                d.u32();
                break;
                case op::CREATE: {
                    auto &x = a.args.emplace<CreateArgs>();
                    x.objType = d.u32();
                    if (x.objType == NF4LNK)
                        x.linkdata = d.string();
                    else if (x.objType == NF4BLK || x.objType == NF4CHR)
                        decodeSpecdata4(d);
                    x.name = d.string();
                    x.attrs = decodeFattr4(d);
                    break;
                }
                case op::DELEGPURGE: case op::RENEW: case op::DESTROY_CLIENTID:
                    d.u64();
                    break;
                case op::DELEGRETURN: case op::FREE_STATEID: case op::OFFLOAD_CANCEL: case op::OFFLOAD_STATUS:
                    skipStateid4(d);
                    break;
                case op::GETATTR: decodeBitmap4(d); break;
                case op::GETFH: case op::LOOKUPP: case op::PUTPUBFH: case op::PUTROOTFH: case op::READLINK:
                case op::RESTOREFH: case op::SAVEFH: case op::ILLEGAL:
                    a.args.emplace<GenericArgs>();
                    break;
                case op::LINK: case op::LOOKUP: case op::REMOVE: case op::SECINFO: case op::GETXATTR:
                case op::REMOVEXATTR:
                    a.args.emplace<NameArgs>().name = d.string();
                    break;
                case op::LOCK: decodeLockArgs(d); break;
                case op::LOCKT:
                d.u32();
                d.u64();
                d.u64();
                stateOwner(d);
                break;
                case op::LOCKU:
                d.u32();
                d.u32();
                skipStateid4(d);
                d.u64();
                d.u64();
                break;
                case op::NVERIFY: case op::VERIFY: decodeFattr4(d); break;
                case op::OPEN: decodeOpenArgs(d, a.args.emplace<OpenArgs>()); break;
                case op::OPENATTR: d.boolean(); break;
                case op::OPEN_CONFIRM:
                skipStateid4(d);
                d.u32();
                break;
                case op::OPEN_DOWNGRADE:
                skipStateid4(d);
                d.u32();
                d.u32();
                d.u32();
                break;
                case op::PUTFH: a.args.emplace<PutfhArgs>().fh = decodeNfsfh4(d); break;
                case op::READ: case op::READ_PLUS: {
                    auto &x = a.args.emplace<ReadArgs>();
                    skipStateid4(d);
                    x.offset = d.u64();
                    x.count = d.u32();
                    break;
                }
                case op::READDIR:
                d.u64();
                decodeVerifier4(d);
                d.u32();
                d.u32();
                decodeBitmap4(d);
                break;
                case op::RENAME: {
                    auto &x = a.args.emplace<RenameArgs>();
                    x.oldname = d.string();
                    x.newname = d.string();
                    break;
                }
                case op::SETATTR: {
                    auto &x = a.args.emplace<SetattrArgs>();
                    skipStateid4(d);
                    x.attrs = decodeFattr4(d);
                    break;
                }
                case op::SETCLIENTID:
                decodeVerifier4(d);
                d.string();
                d.u32();
                netAddr(d);
                d.u32();
                break;
                case op::SETCLIENTID_CONFIRM:
                d.u64();
                decodeVerifier4(d);
                break;
                case op::WRITE: {
                    auto &x = a.args.emplace<WriteArgs>();
                    skipStateid4(d);
                    x.offset = d.u64();
                    d.u32();
                    x.data = d.opaqueVarSpan();
                    break;
                }
                case op::RELEASE_LOCKOWNER: stateOwner(d); break;
                case op::BACKCHANNEL_CTL:
                d.u32();
                repeat(d, 4, cbSecParms);
                break;
                case op::BIND_CONN_TO_SESSION:
                decodeSessionid4(d);
                d.u32();
                d.boolean();
                break;
                case op::EXCHANGE_ID:
                decodeVerifier4(d);
                d.string();
                d.u32();
                protectArgs(d);
                repeat(d, 20, implId);
                break;
                case op::CREATE_SESSION:
                d.u64();
                d.u32();
                d.u32();
                channelAttrs(d);
                channelAttrs(d);
                d.u32();
                repeat(d, 4, cbSecParms);
                break;
                case op::DESTROY_SESSION: decodeSessionid4(d); break;
                case op::GET_DIR_DELEGATION:
                d.boolean();
                decodeBitmap4(d);
                decodeNfstime4(d);
                decodeNfstime4(d);
                decodeBitmap4(d);
                decodeBitmap4(d);
                break;
                case op::GETDEVICEINFO:
                decodeDeviceid4(d);
                d.u32();
                d.u32();
                decodeBitmap4(d);
                break;
                case op::GETDEVICELIST:
                d.u32();
                d.u32();
                d.u64();
                decodeVerifier4(d);
                break;
                case op::LAYOUTCOMMIT:
                d.u64();
                d.u64();
                d.boolean();
                skipStateid4(d);
                if (d.boolean())
                    d.u64();
                if (d.boolean())
                    decodeNfstime4(d);
                layoutUpdate(d);
                break;
                case op::LAYOUTGET:
                d.boolean();
                d.u32();
                d.u32();
                d.u64();
                d.u64();
                d.u64();
                skipStateid4(d);
                d.u32();
                break;
                case op::LAYOUTRETURN: decodeLayoutreturnArgs(d); break;
                case op::SECINFO_NO_NAME: d.u32(); break;
                case op::SEQUENCE:
                decodeSessionid4(d);
                d.u32();
                d.u32();
                d.u32();
                d.boolean();
                break;
                case op::SET_SSV:
                d.opaqueVarSpan();
                d.opaqueVarSpan();
                break;
                case op::TEST_STATEID: repeat(d, 16, skipStateid4); break;
                case op::WANT_DELEGATION: {
                    d.u32();
                    const uint32_t claimType = d.u32();
                    if (claimType == CLAIM_PREVIOUS)
                        d.u32();
                    else if (claimType != CLAIM_FH && claimType != CLAIM_DELEG_PREV_FH)
                        bad("deleg_claim4", claimType);
                    break;
                }
                case op::RECLAIM_COMPLETE: d.boolean(); break;
                case op::ALLOCATE: case op::DEALLOCATE: {
                    auto &x = a.args.emplace<RangeArgs>();
                    skipStateid4(d);
                    x.offset = d.u64();
                    x.length = d.u64();
                    break;
                }
                case op::COPY: decodeCopyArgs(d, a.args.emplace<CopyArgs>()); break;
                case op::COPY_NOTIFY:
                skipStateid4(d);
                netloc(d);
                break;
                case op::IO_ADVISE:
                skipStateid4(d);
                d.u64();
                d.u64();
                decodeBitmap4(d);
                break;
                case op::LAYOUTERROR:
                d.u64();
                d.u64();
                skipStateid4(d);
                repeat(d, 24, [](XdrDecoder &y) {
                    decodeDeviceid4(y);
                    y.u32();
                    y.u32();
                });
                break;
                case op::LAYOUTSTATS:
                d.u64();
                d.u64();
                skipStateid4(d);
                ioInfo(d);
                ioInfo(d);
                decodeDeviceid4(d);
                layoutUpdate(d);
                break;
                case op::SEEK:
                skipStateid4(d);
                d.u64();
                d.u32();
                break;
                case op::WRITE_SAME: decodeWriteSameArgs(d); break;
                case op::CLONE: {
                    auto &x = a.args.emplace<CloneArgs>();
                    skipStateid4(d);
                    skipStateid4(d);
                    x.srcOffset = d.u64();
                    x.dstOffset = d.u64();
                    x.count = d.u64();
                    break;
                }
                case op::SETXATTR:
                d.u32();
                d.string();
                d.opaqueVarSpan();
                break;
                case op::LISTXATTRS:
                d.u64();
                d.u32();
                break;
                default:
                    throw XdrError("unknown operation " + std::to_string(a.op));
            }
            return a;
        }

        namespace {
            ReaddirRes decodeReaddirRes(XdrDecoder &d) {
                ReaddirRes r;
                decodeVerifier4(d);
                while (d.boolean()) {
                    DirEntry4 e;
                    d.u64();
                    e.name = d.string();
                    e.attrs = decodeFattr4(d);
                    r.entries.push_back(std::move(e));
                }
                d.boolean();
                return r;
            }

            OpenRes decodeOpenRes(XdrDecoder &d) {
                OpenRes o;
                skipStateid4(d);
                o.cinfo = decodeChangeInfo4(d);
                d.u32();
                decodeBitmap4(d);
                openDelegation(d);
                return o;
            }

            void secinfo(XdrDecoder &d) {
                const uint32_t flavor = d.u32();
                if (flavor == 6) {
                    d.string();
                    d.u32();
                    d.u32();
                }
            }

            ReadPlusContent readPlusContent(XdrDecoder &d) {
                ReadPlusContent c;
                c.type = d.u32();
                if (c.type == NFS4_CONTENT_DATA) {
                    c.offset = d.u64();
                    c.data = d.opaqueVarSpan();
                } else if (c.type == NFS4_CONTENT_HOLE) {
                    c.offset = d.u64();
                    c.length = d.u64();
                } else {
                    bad("data_content4", c.type);
                }
                return c;
            }

            void layout(XdrDecoder &d) {
                d.u64();
                d.u64();
                d.u32();
                d.u32();
                d.opaqueVarSpan();
            }

            void decodeResBody(XdrDecoder &d, ResOp &r) {
                const bool ok = r.status == NFS4_OK;
                switch (r.op) {
                    case op::ACCESS:
                        if (ok) {
                            d.u32();
                            d.u32();
                        }
                        break;
                    case op::CLOSE: case op::OPEN_CONFIRM: case op::OPEN_DOWNGRADE: case op::LOCKU:
                        if (ok)
                            skipStateid4(d);
                        break;
                    case op::COMMIT:
                        if (ok)
                            decodeVerifier4(d);
                        break;
                    case op::CREATE:
                        if (ok) {
                            decodeChangeInfo4(d);
                            decodeBitmap4(d);
                        }
                        break;
                    case op::GETATTR:
                        if (ok)
                            r.res.emplace<GetattrRes>().attrs = decodeFattr4(d);
                        break;
                    case op::GETFH:
                        if (ok)
                            r.res.emplace<GetfhRes>().fh = decodeNfsfh4(d);
                        break;
                    case op::LINK: case op::REMOVE: case op::SETXATTR: case op::REMOVEXATTR:
                        if (ok)
                            decodeChangeInfo4(d);
                        break;
                    case op::RENAME:
                        if (ok) {
                            decodeChangeInfo4(d);
                            decodeChangeInfo4(d);
                        }
                        break;
                    case op::LOCK:
                        if (ok)
                            skipStateid4(d);
                        else if (r.status == NFS4ERR_DENIED)
                            lockDenied(d);
                        break;
                    case op::LOCKT:
                        if (r.status == NFS4ERR_DENIED)
                            lockDenied(d);
                        break;
                    case op::OPEN:
                        if (ok)
                            r.res = decodeOpenRes(d);
                        break;
                    case op::READ:
                        if (ok) {
                            auto &x = r.res.emplace<ReadRes>();
                            d.boolean();
                            x.data = d.opaqueVarSpan();
                        }
                        break;
                    case op::READDIR:
                        if (ok)
                            r.res = decodeReaddirRes(d);
                        break;
                    case op::READLINK:
                        if (ok)
                            r.res.emplace<ReadlinkRes>().link = d.string();
                        break;
                    case op::SECINFO: case op::SECINFO_NO_NAME:
                        if (ok)
                            repeat(d, 4, secinfo);
                        break;
                    case op::SETATTR:
                        decodeBitmap4(d); // present for every status
                        break;
                    case op::SETCLIENTID:
                        if (ok) {
                            d.u64();
                            decodeVerifier4(d);
                        } else if (r.status == NFS4ERR_CLID_INUSE) {
                            netAddr(d);
                        }
                        break;
                    case op::WRITE:
                        if (ok) {
                            auto &x = r.res.emplace<WriteRes>();
                            x.count = d.u32();
                            d.u32();
                            decodeVerifier4(d);
                        }
                        break;
                    case op::BIND_CONN_TO_SESSION:
                        if (ok) {
                            decodeSessionid4(d);
                            d.u32();
                            d.boolean();
                        }
                        break;
                    case op::EXCHANGE_ID:
                        if (ok) {
                            d.u64();
                            d.u32();
                            d.u32();
                            protectRes(d);
                            d.u64();
                            d.string();
                            d.string();
                            repeat(d, 20, implId);
                        }
                        break;
                    case op::CREATE_SESSION:
                        if (ok) {
                            decodeSessionid4(d);
                            d.u32();
                            d.u32();
                            channelAttrs(d);
                            channelAttrs(d);
                        }
                        break;
                    case op::GET_DIR_DELEGATION:
                        if (ok) {
                            const uint32_t st = d.u32();
                            if (st == 0) {
                                decodeVerifier4(d);
                                skipStateid4(d);
                                decodeBitmap4(d);
                                decodeBitmap4(d);
                                decodeBitmap4(d);
                            } else if (st == 1) {
                                d.boolean();
                            } else {
                                bad("gddrnf4_status", st);
                            }
                        }
                        break;
                    case op::GETDEVICEINFO:
                        if (ok) {
                            d.u32();
                            d.opaqueVarSpan();
                            decodeBitmap4(d);
                        } else if (r.status == NFS4ERR_TOOSMALL) {
                            d.u32();
                        }
                        break;
                    case op::GETDEVICELIST:
                        if (ok) {
                            d.u64();
                            decodeVerifier4(d);
                            repeat(d, 16, decodeDeviceid4);
                            d.boolean();
                        }
                        break;
                    case op::LAYOUTCOMMIT:
                        if (ok && d.boolean())
                            d.u64();
                        break;
                    case op::LAYOUTGET:
                        if (ok) {
                            d.boolean();
                            skipStateid4(d);
                            repeat(d, 28, layout);   // offset 8 + length 8 + iomode 4 + type 4 + empty body 4
                        } else if (r.status == NFS4ERR_LAYOUTTRYLATER) {
                            d.boolean();
                        }
                        break;
                    case op::LAYOUTRETURN:
                        if (ok && d.boolean())
                            skipStateid4(d);
                        break;
                    case op::SEQUENCE:
                        if (ok) {
                            decodeSessionid4(d);
                            d.u32();
                            d.u32();
                            d.u32();
                            d.u32();
                            d.u32();
                        }
                        break;
                    case op::SET_SSV:
                        if (ok)
                            d.opaqueVarSpan();
                        break;
                    case op::TEST_STATEID:
                        if (ok)
                            repeat(d, 4, [](XdrDecoder &y) { y.u32(); });
                        break;
                    case op::WANT_DELEGATION:
                        if (ok)
                            openDelegation(d);
                        break;
                    case op::COPY:
                        if (ok) {
                            auto &x = r.res.emplace<CopyRes>();
                            x.count = writeResponse(d);
                            copyReqs(d);
                        } else if (r.status == NFS4ERR_OFFLOAD_NO_REQS) {
                            r.res.emplace<CopyRes>();
                            copyReqs(d);
                        }
                        break;
                    case op::COPY_NOTIFY:
                        if (ok) {
                            decodeNfstime4(d);
                            skipStateid4(d);
                            repeat(d, 8, netloc);
                        }
                        break;
                    case op::OFFLOAD_STATUS:
                        if (ok) {
                            d.u64();
                            const uint32_t n = d.arrayCount();
                            for (uint32_t i = 0; i < n; ++i)
                                d.u32();
                        }
                        break;
                    case op::IO_ADVISE:
                        if (ok)
                            decodeBitmap4(d);
                        break;
                    case op::READ_PLUS:
                        if (ok) {
                            auto &x = r.res.emplace<ReadPlusRes>();
                            d.boolean();
                            x.contents = vec(d, 12, readPlusContent);
                        }
                        break;
                    case op::SEEK:
                        if (ok) {
                            d.boolean();
                            d.u64();
                        }
                        break;
                    case op::WRITE_SAME:
                        if (ok)
                            writeResponse(d);
                        break;
                    case op::GETXATTR:
                        if (ok)
                            d.opaqueVarSpan();
                        break;
                    case op::LISTXATTRS:
                        if (ok) {
                            d.u64();
                            repeat(d, 4, skipString);
                            d.boolean();
                        }
                        break;
                    case op::DELEGPURGE: case op::DELEGRETURN: case op::LOOKUP: case op::LOOKUPP: case op::NVERIFY:
                    case op::OPENATTR: case op::PUTFH: case op::PUTPUBFH: case op::PUTROOTFH: case op::RENEW:
                    case op::RESTOREFH: case op::SAVEFH: case op::SETCLIENTID_CONFIRM: case op::VERIFY:
                    case op::RELEASE_LOCKOWNER: case op::BACKCHANNEL_CTL: case op::DESTROY_SESSION:
                    case op::FREE_STATEID: case op::DESTROY_CLIENTID: case op::RECLAIM_COMPLETE:
                    case op::ALLOCATE: case op::DEALLOCATE: case op::LAYOUTERROR: case op::LAYOUTSTATS:
                    case op::OFFLOAD_CANCEL: case op::CLONE: case op::ILLEGAL:
                        break;
                    default:
                        throw XdrError("unknown operation " + std::to_string(r.op));
                }
            }

            template <typename Ops, typename F>
            void decodeOps(XdrDecoder &d, uint32_t n, Ops &ops, bool &complete, F decodeOne) {
                for (uint32_t i = 0; i < n; ++i) {
                    if (i >= MAX_COMPOUND_OPS)
                        return;
                    try {
                        ops.push_back(decodeOne(d));
                    } catch (const XdrError &) {
                        return;     // truncated or unknown op: complete stays false
                    }
                }
                complete = true;
            }
        }

        ResOp decodeResOp(XdrDecoder &d) {
            ResOp r;
            r.op = d.u32();
            r.status = d.u32();
            decodeResBody(d, r);
            return r;
        }

        CompoundArgs decodeCompoundArgs(XdrDecoder &d) {
            CompoundArgs c;
            try {
                d.string();
                d.u32();
                const uint32_t n = d.u32();
                decodeOps(d, n, c.ops, c.complete, decodeArgOp);
            } catch (const XdrError &) {
                // header truncated: complete stays false
            }
            return c;
        }

        CompoundRes decodeCompoundRes(XdrDecoder &d) {
            CompoundRes c;
            try {
                c.status = d.u32();
                d.string();
                const uint32_t n = d.u32();
                decodeOps(d, n, c.ops, c.complete, decodeResOp);
            } catch (const XdrError &) {
                // header truncated: complete stays false
            }
            return c;
        }

        namespace {
            CbArgOp decodeCbArgOp(XdrDecoder &d) {
                CbArgOp a;
                a.op = d.u32();
                switch (a.op) {
                    case op::CB_GETATTR:
                    decodeNfsfh4(d);
                    decodeBitmap4(d);
                    break;
                    case op::CB_RECALL:
                    skipStateid4(d);
                    d.boolean();
                    decodeNfsfh4(d);
                    break;
                    case op::CB_LAYOUTRECALL: {
                        d.u32();
                        d.u32();
                        d.boolean();
                        const uint32_t recallType = d.u32();
                        if (recallType == 1) {
                            decodeNfsfh4(d);
                            d.u64();
                            d.u64();
                            skipStateid4(d);
                        } else if (recallType == 2) {
                            decodeFsid4(d);
                        } else if (recallType != 3) {
                            bad("layoutrecall_type4", recallType);
                        }
                        break;
                    }
                    case op::CB_NOTIFY:
                    skipStateid4(d);
                    decodeNfsfh4(d);
                    repeat(d, 8, notify);
                    break;
                    case op::CB_PUSH_DELEG:
                    decodeNfsfh4(d);
                    openDelegation(d);
                    break;
                    case op::CB_RECALL_ANY: case op::CB_RECALLABLE_OBJ_AVAIL:
                    d.u32();
                    decodeBitmap4(d);
                    break;
                    case op::CB_RECALL_SLOT:
                        d.u32();
                        break;
                    case op::CB_SEQUENCE:
                    decodeSessionid4(d);
                    d.u32();
                    d.u32();
                    d.u32();
                    d.boolean();
                    repeat(d, 20, [](XdrDecoder &y) {
                        decodeSessionid4(y);
                        for (uint32_t n = y.arrayCount(8); n > 0; --n) {
                            y.u32();
                            y.u32();
                        }
                    });
                    break;
                    case op::CB_WANTS_CANCELLED:
                    d.boolean();
                    d.boolean();
                    break;
                    case op::CB_NOTIFY_LOCK:
                    decodeNfsfh4(d);
                    stateOwner(d);
                    break;
                    case op::CB_NOTIFY_DEVICEID:
                        repeat(d, 8, notify);
                        break;
                    case op::CB_OFFLOAD: {
                        decodeNfsfh4(d);
                        skipStateid4(d);
                        const uint32_t status = d.u32();
                        if (status == NFS4_OK)
                            writeResponse(d);
                        else
                            d.u64();
                        break;
                    }
                    case op::CB_ILLEGAL:
                        a.args.emplace<GenericArgs>();
                        break;
                    default:
                        throw XdrError("unknown callback operation " + std::to_string(a.op));
                }
                return a;
            }

            CbResOp decodeCbResOp(XdrDecoder &d) {
                CbResOp r;
                r.op = d.u32();
                r.status = d.u32();
                switch (r.op) {
                    case op::CB_GETATTR:
                        if (r.status == NFS4_OK)
                            decodeFattr4(d);
                        break;
                    case op::CB_SEQUENCE:
                        if (r.status == NFS4_OK) {
                            decodeSessionid4(d);
                            d.u32();
                            d.u32();
                            d.u32();
                            d.u32();
                        }
                        break;
                    case op::CB_RECALL: case op::CB_LAYOUTRECALL: case op::CB_NOTIFY: case op::CB_PUSH_DELEG:
                    case op::CB_RECALL_ANY: case op::CB_RECALLABLE_OBJ_AVAIL: case op::CB_RECALL_SLOT:
                    case op::CB_WANTS_CANCELLED: case op::CB_NOTIFY_LOCK: case op::CB_NOTIFY_DEVICEID:
                    case op::CB_OFFLOAD: case op::CB_ILLEGAL:
                        break;
                    default:
                        throw XdrError("unknown callback operation " + std::to_string(r.op));
                }
                return r;
            }
        }

        CbCompoundArgs decodeCbCompoundArgs(XdrDecoder &d) {
            CbCompoundArgs c;
            try {
                d.string();
                d.u32();
                d.u32();
                const uint32_t n = d.u32();
                decodeOps(d, n, c.ops, c.complete, decodeCbArgOp);
            } catch (const XdrError &) {
                // header truncated: complete stays false
            }
            return c;
        }

        CbCompoundRes decodeCbCompoundRes(XdrDecoder &d) {
            CbCompoundRes c;
            try {
                c.status = d.u32();
                d.string();
                const uint32_t n = d.u32();
                decodeOps(d, n, c.ops, c.complete, decodeCbResOp);
            } catch (const XdrError &) {
                // header truncated: complete stays false
            }
            return c;
        }

    }
}
