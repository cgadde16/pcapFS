#include "nfs4_attrs.h"

#include <algorithm>
#include <cstdio>

namespace pcapfs {
    namespace nfs {

        namespace {
            enum class Kind {
                U32, U64, Bool, Time, SetTime, Fsid, Spec, Bitmap, Fh, String, Acl, NfsAcl41, FsLocations,
                FsStatus, U32Array, LayoutHint, FsLocationsInfo, MdsThreshold, RetentionGet, RetentionSet,
                ModeMasked, SecLabel, OpenArgs
            };

            // indexed by attribute number (RFC 8881 section 5, RFC 7863, RFC 8275, RFC 8276, RFC 9754)
            const Kind ATTRS[] = {
                Kind::Bitmap,          // 0 supported_attrs
                Kind::U32,             // 1 type
                Kind::U32,             // 2 fh_expire_type
                Kind::U64,             // 3 change
                Kind::U64,             // 4 size
                Kind::Bool,            // 5 link_support
                Kind::Bool,            // 6 symlink_support
                Kind::Bool,            // 7 named_attr
                Kind::Fsid,            // 8 fsid
                Kind::Bool,            // 9 unique_handles
                Kind::U32,             // 10 lease_time
                Kind::U32,             // 11 rdattr_error
                Kind::Acl,             // 12 acl
                Kind::U32,             // 13 aclsupport
                Kind::Bool,            // 14 archive
                Kind::Bool,            // 15 cansettime
                Kind::Bool,            // 16 case_insensitive
                Kind::Bool,            // 17 case_preserving
                Kind::Bool,            // 18 chown_restricted
                Kind::Fh,              // 19 filehandle
                Kind::U64,             // 20 fileid
                Kind::U64,             // 21 files_avail
                Kind::U64,             // 22 files_free
                Kind::U64,             // 23 files_total
                Kind::FsLocations,     // 24 fs_locations
                Kind::Bool,            // 25 hidden
                Kind::Bool,            // 26 homogeneous
                Kind::U64,             // 27 maxfilesize
                Kind::U32,             // 28 maxlink
                Kind::U32,             // 29 maxname
                Kind::U64,             // 30 maxread
                Kind::U64,             // 31 maxwrite
                Kind::String,          // 32 mimetype
                Kind::U32,             // 33 mode
                Kind::Bool,            // 34 no_trunc
                Kind::U32,             // 35 numlinks
                Kind::String,          // 36 owner
                Kind::String,          // 37 owner_group
                Kind::U64,             // 38 quota_avail_hard
                Kind::U64,             // 39 quota_avail_soft
                Kind::U64,             // 40 quota_used
                Kind::Spec,            // 41 rawdev
                Kind::U64,             // 42 space_avail
                Kind::U64,             // 43 space_free
                Kind::U64,             // 44 space_total
                Kind::U64,             // 45 space_used
                Kind::Bool,            // 46 system
                Kind::Time,            // 47 time_access
                Kind::SetTime,         // 48 time_access_set
                Kind::Time,            // 49 time_backup
                Kind::Time,            // 50 time_create
                Kind::Time,            // 51 time_delta
                Kind::Time,            // 52 time_metadata
                Kind::Time,            // 53 time_modify
                Kind::SetTime,         // 54 time_modify_set
                Kind::U64,             // 55 mounted_on_fileid
                Kind::Time,            // 56 dir_notif_delay
                Kind::Time,            // 57 dirent_notif_delay
                Kind::NfsAcl41,        // 58 dacl
                Kind::NfsAcl41,        // 59 sacl
                Kind::Fsid,            // 60 change_policy
                Kind::FsStatus,        // 61 fs_status
                Kind::U32Array,        // 62 fs_layout_types
                Kind::LayoutHint,      // 63 layout_hint
                Kind::U32Array,        // 64 layout_types
                Kind::U32,             // 65 layout_blksize
                Kind::U32,             // 66 layout_alignment
                Kind::FsLocationsInfo, // 67 fs_locations_info
                Kind::MdsThreshold,    // 68 mdsthreshold
                Kind::RetentionGet,    // 69 retention_get
                Kind::RetentionSet,    // 70 retention_set
                Kind::RetentionGet,    // 71 retentevt_get
                Kind::RetentionSet,    // 72 retentevt_set
                Kind::U64,             // 73 retention_hold
                Kind::ModeMasked,      // 74 mode_set_masked
                Kind::Bitmap,          // 75 suppattr_exclcreat
                Kind::U32,             // 76 fs_charset_cap
                Kind::U32,             // 77 clone_blksize
                Kind::U64,             // 78 space_freed
                Kind::U32,             // 79 change_attr_type
                Kind::SecLabel,        // 80 sec_label
                Kind::ModeMasked,      // 81 mode_umask
                Kind::Bool,            // 82 xattr_support
                Kind::Bool,            // 83 offline
                Kind::Time,            // 84 time_deleg_access
                Kind::Time,            // 85 time_deleg_modify
                Kind::OpenArgs         // 86 open_arguments
            };
            constexpr unsigned NUM_ATTRS = sizeof(ATTRS) / sizeof(ATTRS[0]);
            static_assert(NUM_ATTRS == 87, "attribute table must cover 0..86");

            void skipString(XdrDecoder &d) { d.opaqueVarSpan(); }
            void skipPathname(XdrDecoder &d) {
                for (uint32_t n = d.arrayCount(); n > 0; --n)
                    skipString(d);
            }
            void skipAce(XdrDecoder &d) {
                d.skip(12); // type, flag, access_mask
                skipString(d);
            }
            void skipAceArray(XdrDecoder &d) {
                for (uint32_t n = d.arrayCount(16); n > 0; --n)
                    skipAce(d);
            }

            void skipKind(Kind k, XdrDecoder &d) {
                switch (k) {
                    case Kind::U32: case Kind::Bool: d.skip(4); break;
                    case Kind::U64: d.skip(8); break;
                    case Kind::Time: d.skip(12); break;
                    case Kind::Fsid: d.skip(16); break;
                    case Kind::Spec: case Kind::ModeMasked: d.skip(8); break;
                    case Kind::SetTime:
                        if (d.u32() == 1)
                            d.skip(12);
                        break;
                    case Kind::Bitmap:
                        decodeBitmap4(d);
                        break;
                    case Kind::Fh:
                        d.opaqueVarSpan(128);
                        break;
                    case Kind::String:
                        skipString(d);
                        break;
                    case Kind::Acl:
                        skipAceArray(d);
                        break;
                    case Kind::NfsAcl41:
                        d.skip(4); // na41_flag
                        skipAceArray(d);
                        break;
                    case Kind::FsLocations:
                        skipPathname(d);
                        for (uint32_t n = d.arrayCount(8); n > 0; --n) {
                            for (uint32_t m = d.arrayCount(); m > 0; --m)
                                skipString(d); // server<>
                            skipPathname(d);
                        }
                        break;
                    case Kind::FsStatus:
                        d.skip(8); // fss_absent, fss_type
                        skipString(d);
                        skipString(d);
                        d.skip(4 + 12); // fss_age, fss_version
                        break;
                    case Kind::U32Array:
                        d.skip(static_cast<size_t>(d.arrayCount()) * 4);
                        break;
                    case Kind::LayoutHint:
                        d.skip(4);
                        skipString(d);
                        break;
                    case Kind::FsLocationsInfo:
                        d.skip(8); // fli_flags, fli_valid_for
                        skipPathname(d);
                        for (uint32_t n = d.arrayCount(8); n > 0; --n) {
                            for (uint32_t m = d.arrayCount(12); m > 0; --m) {
                                d.skip(4); // fls_currency
                                skipString(d);
                                skipString(d);
                            }
                            skipPathname(d);
                        }
                        break;
                    case Kind::MdsThreshold:
                        for (uint32_t n = d.arrayCount(12); n > 0; --n) {
                            d.skip(4);
                            decodeBitmap4(d);
                            skipString(d);
                        }
                        break;
                    case Kind::RetentionGet:
                        d.skip(8);
                        d.skip(static_cast<size_t>(d.arrayCount(12)) * 12);
                        break;
                    case Kind::RetentionSet:
                        d.skip(4);
                        d.skip(static_cast<size_t>(d.arrayCount(8)) * 8);
                        break;
                    case Kind::SecLabel:
                        d.skip(8);
                        skipString(d);
                        break;
                    case Kind::OpenArgs:
                        for (int i = 0; i < 5; ++i)
                            decodeBitmap4(d); // oa_share_access, oa_share_deny, oa_share_access_want, oa_open_claim, oa_create_mode
                        break;
                }
            }

            void decodeAttr(unsigned a, XdrDecoder &d, Fattr4 &f) {
                switch (a) {
                    case 1: f.type = d.u32(); break;
                    case 4: f.size = d.u64(); break;
                    case 8: f.fsid = decodeFsid4(d); break;
                    case 19: f.filehandle = decodeNfsfh4(d); break;
                    case 20: f.fileid = d.u64(); break;
                    case 33: f.mode = d.u32(); break;
                    case 36: f.owner = d.string(); break;
                    case 37: f.ownerGroup = d.string(); break;
                    case 47: f.timeAccess = decodeNfstime4(d); break;
                    case 50: f.timeCreate = decodeNfstime4(d); break;
                    case 52: f.timeMetadata = decodeNfstime4(d); break;
                    case 53: f.timeModify = decodeNfstime4(d); break;
                    default: skipKind(ATTRS[a], d); break;
                }
            }

            template <size_t N>
            std::array<uint8_t, N> fixedArray(XdrDecoder &d) {
                std::array<uint8_t, N> a{};
                const std::string_view v = d.opaqueFixed(N);
                for (size_t i = 0; i < N; ++i)
                    a[i] = static_cast<uint8_t>(v[i]);
                return a;
            }
        }

        std::vector<unsigned> Bitmap4::set() const {
            std::vector<unsigned> r;
            for (size_t w = 0; w < words.size(); ++w)
                for (unsigned b = 0; b < 32; ++b)
                    if (words[w] & (1u << b))
                        r.push_back(static_cast<unsigned>(w * 32 + b));
            return r;
        }

        Bitmap4 decodeBitmap4(XdrDecoder &dec) {
            // bitmaps in real traffic have at most 3 words (attributes 0..86); longer ones are only accepted
            // if the extra words are empty
            static constexpr uint32_t MAX_BITMAP_WORDS = 8;
            Bitmap4 b;
            const uint32_t n = dec.arrayCount();
            b.words.reserve(std::min(n, MAX_BITMAP_WORDS));
            for (uint32_t i = 0; i < n; ++i) {
                const uint32_t word = dec.u32();
                if (i < MAX_BITMAP_WORDS)
                    b.words.push_back(word);
                else if (word != 0)
                    throw XdrError("XDR: bitmap4 with " + std::to_string(n) + " words sets bits past word " +
                                   std::to_string(MAX_BITMAP_WORDS));
            }
            return b;
        }

        Nfstime4 decodeNfstime4(XdrDecoder &dec) {
            Nfstime4 t;
            t.seconds = dec.i64();
            t.nseconds = dec.u32();
            return t;
        }

        Fsid4 decodeFsid4(XdrDecoder &dec) {
            Fsid4 f;
            f.major = dec.u64();
            f.minor = dec.u64();
            return f;
        }

        void decodeSpecdata4(XdrDecoder &dec) {
            dec.u32();
            dec.u32();
        }

        ChangeInfo4 decodeChangeInfo4(XdrDecoder &dec) {
            ChangeInfo4 c;
            dec.boolean();
            c.before = dec.u64();
            c.after = dec.u64();
            return c;
        }

        void skipStateid4(XdrDecoder &dec) {
            dec.skip(16);
        }

        Nfsfh4 decodeNfsfh4(XdrDecoder &dec) {
            return std::string(dec.opaqueVar(128));
        }

        Verifier4 decodeVerifier4(XdrDecoder &dec) { return fixedArray<8>(dec); }
        Sessionid4 decodeSessionid4(XdrDecoder &dec) { return fixedArray<16>(dec); }
        Deviceid4 decodeDeviceid4(XdrDecoder &dec) { return fixedArray<16>(dec); }

        Fattr4 decodeFattr4(XdrDecoder &dec) {
            Fattr4 f;
            const Bitmap4 attrmask = decodeBitmap4(dec);
            const Span rawValues = dec.opaqueVarSpan();
            XdrDecoder vals(dec.data() + rawValues.offset, rawValues.length);
            for (unsigned a : attrmask.set()) {
                if (a >= NUM_ATTRS)
                    return f;
                try {
                    decodeAttr(a, vals, f);
                } catch (const XdrError &) {
                    return f;
                }
            }
            return f;
        }

        std::string escapeWireString(std::string_view s) {
            std::string o;
            o.reserve(s.size());
            for (unsigned char ch : s) {
                if (ch == '"' || ch == '\\') {
                    o += '\\';
                    o += static_cast<char>(ch);
                } else if (ch < 0x20 || ch == 0x7f) {
                    char b[8];
                    std::snprintf(b, sizeof(b), "\\x%02x", ch);
                    o += b;
                } else {
                    o += static_cast<char>(ch);
                }
            }
            return o;
        }

    }
}
