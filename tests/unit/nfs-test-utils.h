#ifndef PCAPFS_TESTS_NFS_TEST_UTILS_H
#define PCAPFS_TESTS_NFS_TEST_UTILS_H

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "../../src/virtualfiles/nfs.h"
#include "../../src/config.h"

namespace pcapfs {
    namespace nfstest {
        using Buf = std::vector<uint8_t>;

        inline void put32(Buf &b, uint32_t v) {
            for (int shift = 24; shift >= 0; shift -= 8)
                b.push_back(static_cast<uint8_t>(v >> shift));
        }

        inline void put64(Buf &b, uint64_t v) {
            put32(b, static_cast<uint32_t>(v >> 32));
            put32(b, static_cast<uint32_t>(v));
        }

        // variable length opaque or string: length, data, zero padding to 4 bytes
        inline void putOpaque(Buf &b, const std::string &s) {
            put32(b, static_cast<uint32_t>(s.size()));
            b.insert(b.end(), s.begin(), s.end());
            while (b.size() % 4 != 0)
                b.push_back(0);
        }

        inline void append(Buf &dst, const Buf &src) { dst.insert(dst.end(), src.begin(), src.end()); }

        // RPC record mark: length and last-fragment flag
        inline Buf recordMark(uint32_t length, bool last) {
            Buf b;
            put32(b, length | (last ? 0x80000000u : 0));
            return b;
        }

        // payload as a single-fragment record
        inline Buf withMark(const Buf &payload) {
            Buf out = recordMark(static_cast<uint32_t>(payload.size()), true);
            append(out, payload);
            return out;
        }

        // File::config is a protected static; this gives the tests access
        struct ConfigAccess : public NfsFile {
            static options::PcapFsOptions &ref() { return config; }
        };

        // RAII: restores the config and the snapshot / snip flags
        struct ConfigGuard {
            options::PcapFsOptions saved = ConfigAccess::ref();
            bool snapshot = options::SNAPSHOT_SPECIFIED;
            bool lower = options::LOWER_SNIP_SPECIFIED;
            bool upper = options::UPPER_SNIP_SPECIFIED;
            ~ConfigGuard() {
                ConfigAccess::ref() = saved;
                options::SNAPSHOT_SPECIFIED = snapshot;
                options::LOWER_SNIP_SPECIFIED = lower;
                options::UPPER_SNIP_SPECIFIED = upper;
            }
            void mode(options::TimestampMode m) { ConfigAccess::ref().timestampMode = m; }
            void snapshotAt(const TimePoint &t) {
                ConfigAccess::ref().snapshot = t;
                options::SNAPSHOT_SPECIFIED = true;
            }
            // an empty bound is not specified
            void snip(const std::optional<TimePoint> &from, const std::optional<TimePoint> &to) {
                options::LOWER_SNIP_SPECIFIED = from.has_value();
                options::UPPER_SNIP_SPECIFIED = to.has_value();
                ConfigAccess::ref().snip = {from.value_or(TimePoint{}), to.value_or(TimePoint{})};
            }
        };
    }
}

#endif
