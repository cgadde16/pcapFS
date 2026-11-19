#include <catch2/catch.hpp>

#include <cstdint>
#include <vector>

#include "../../src/virtualfiles/nfs/xdr.h"

using pcapfs::nfs::XdrDecoder;
using pcapfs::nfs::XdrError;

TEST_CASE("NFS xdr: integers and bool", "[nfs]") {
    const std::vector<uint8_t> d = {0, 0, 0, 5, 0xff, 0xff, 0xff, 0xfe,
                                    1, 2, 3, 4, 5, 6, 7, 8,
                                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                    0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2};
    XdrDecoder dec(d.data(), d.size());
    REQUIRE(dec.u32() == 5);
    REQUIRE(dec.u32() == 0xfffffffeu);
    REQUIRE(dec.u64() == 0x0102030405060708ULL);
    REQUIRE(dec.i64() == -1);
    REQUIRE(dec.boolean() == true);
    REQUIRE(dec.boolean() == false);
    REQUIRE_THROWS_AS(dec.boolean(), XdrError);
    REQUIRE(dec.remaining() == 0);
    REQUIRE_THROWS_AS(dec.u32(), XdrError);
}

TEST_CASE("NFS xdr: string and opaque with padding", "[nfs]") {
    const std::vector<uint8_t> d = {0, 0, 0, 3, 'a', 'b', 'c', 0,
                                    0, 0, 0, 4, 'w', 'x', 'y', 'z',
                                    0, 0, 0, 0,
                                    'q', 'r', 0, 0,
                                    0, 0, 0, 5, 1, 2, 3, 4, 5, 0, 0, 0};
    XdrDecoder dec(d.data(), d.size());
    REQUIRE(dec.string() == "abc");
    REQUIRE(dec.pos() == 8);
    REQUIRE(dec.opaqueVar() == "wxyz");
    REQUIRE(dec.opaqueVar().empty());
    REQUIRE(dec.opaqueFixed(2) == "qr");
    REQUIRE(dec.pos() == 24);
    const auto span = dec.opaqueVarSpan();
    REQUIRE(span.offset == 28);
    REQUIRE(span.length == 5);
    REQUIRE(dec.remaining() == 0);
}

TEST_CASE("NFS xdr: truncation and oversize", "[nfs]") {
    SECTION("declared length larger than data") {
        const std::vector<uint8_t> d = {0, 0, 0, 8, 'a', 'b'};
        XdrDecoder dec(d.data(), d.size());
        REQUIRE_THROWS_AS(dec.opaqueVar(), XdrError);
    }
    SECTION("huge declared length does not overflow") {
        const std::vector<uint8_t> d = {0xff, 0xff, 0xff, 0xff, 'a', 'b', 'c', 'd'};
        XdrDecoder dec(d.data(), d.size());
        REQUIRE_THROWS_AS(dec.string(0xffffffffu), XdrError);
        dec.seek(0);
        REQUIRE_THROWS_AS(dec.opaqueVarSpan(0xffffffffu), XdrError);
    }
    SECTION("maxLen") {
        const std::vector<uint8_t> d = {0, 0, 0, 4, 'a', 'b', 'c', 'd'};
        XdrDecoder dec(d.data(), d.size());
        REQUIRE_THROWS_AS(dec.string(3), XdrError);
    }
    SECTION("missing padding") {
        const std::vector<uint8_t> d = {0, 0, 0, 3, 'a', 'b', 'c'};
        XdrDecoder dec(d.data(), d.size());
        REQUIRE_THROWS_AS(dec.string(), XdrError);
    }
    SECTION("short integers") {
        const std::vector<uint8_t> d = {0, 0, 0, 1, 0, 0, 0};
        XdrDecoder dec(d.data(), d.size());
        REQUIRE_THROWS_AS(dec.u64(), XdrError);
        REQUIRE(dec.pos() == 0);
        REQUIRE_THROWS_AS(dec.opaqueFixed(100), XdrError);
        REQUIRE_THROWS_AS(dec.skip(static_cast<size_t>(-1)), XdrError);
    }
    SECTION("seek") {
        const std::vector<uint8_t> d = {0, 0, 0, 1};
        XdrDecoder dec(d.data(), d.size());
        dec.seek(4);
        REQUIRE(dec.remaining() == 0);
        REQUIRE_THROWS_AS(dec.seek(5), XdrError);
    }
}

TEST_CASE("NFS xdr: skip aligns to 4", "[nfs]") {
    const std::vector<uint8_t> d(16, 0);
    XdrDecoder dec(d.data(), d.size());
    dec.skip(1);
    REQUIRE(dec.pos() == 4);
    dec.skip(4);
    REQUIRE(dec.pos() == 8);
    dec.skip(5);
    REQUIRE(dec.pos() == 16);
    REQUIRE(dec.data() == d.data());
}
