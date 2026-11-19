"""System tests for the NFSv4 reconstruction.
nfs-system-tests.pcap is one NFSv4.2 connection (client 10.200.0.2, server 10.200.0.1);
the workload steps are listed at the T_* constants below.
"""

import hashlib
import os
import random
import string
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path

import pytest

SERVER_DIR = "nfs/10.200.0.1"
MINI = SERVER_DIR + "/mini"
CONTROL_FILE = "nfs/0-0_NFS.control.meta"
RPC_CALLS = 117  # calls in the capture, each with its reply

HELLO_V0 = b"hello from the pcapFS NFS system test\n"
HELLO_V1 = HELLO_V0 + b"written through the hard link\n"
_LINE = b"pcapFS NFSv4.2 ALLOCATE/DEALLOCATE test line\n"
HOLES_V0 = (_LINE * 500)[:20000]
_holes_v1 = bytearray(HOLES_V0)
_holes_v1[4096:12288] = bytes(8192)
HOLES_V1 = bytes(_holes_v1)  # after DEALLOCATE (hole punched, still 20000 bytes)
HOLES_V2 = HOLES_V1 + bytes(32768 - 20000)  # after ALLOCATE beyond EOF

# packet times (unix seconds, UTC) of the workload steps
T_WRITE = 1794258806  # mkdir mini/sub, hello.txt and holes.bin written
T_FIRST_READ = 1794258808  # both files read
T_LINK = 1794258809  # LINK, WRITE through the link, REMOVE hello.txt, READ the link
T_FALLOCATE = 1794258811  # DEALLOCATE, ALLOCATE, READ holes.bin
T_RENAME = 1794258813  # RENAME holes.bin, symlink created
T_GONE = 1794258814  # gone.txt written and removed, ls -la, stat, readlink


class TestNfsBasicFunctionality:
    def test_pcap_gets_mounted(self, testpcap):
        with mount_pcap(testpcap) as mountpoint:
            assert os.path.ismount(mountpoint)

    def test_mount_point_contains_reconstructed_tree(
        self, testpcap, expected_nfs_files
    ):
        with mount_pcap(testpcap) as mountpoint:
            assert Path(mountpoint, MINI, "sub").is_dir()
            assert get_nfs_file_list(mountpoint) == expected_nfs_files

    def test_show_metadata_adds_control_file_and_symlink(
        self, testpcap, expected_nfs_files_with_metadata
    ):
        with mount_pcap(testpcap, params=["--show-metadata"]) as mountpoint:
            assert get_nfs_file_list(mountpoint) == expected_nfs_files_with_metadata


class TestNfsFileContents:
    def test_file_versions(self, testpcap):
        with mount_pcap(testpcap) as mountpoint:
            assert read_file(mountpoint, MINI + "/hello.txt@0") == HELLO_V0
            assert read_file(mountpoint, MINI + "/hello.txt@1") == HELLO_V1

    def test_hard_link_shares_the_content(self, testpcap):
        with mount_pcap(testpcap) as mountpoint:
            assert read_file(mountpoint, MINI + "/sub/hello-link.txt@0") == HELLO_V0
            assert read_file(mountpoint, MINI + "/sub/hello-link.txt@1") == HELLO_V1

    def test_sparse_file_after_deallocate_and_allocate(self, testpcap):
        with mount_pcap(testpcap) as mountpoint:
            assert read_file(mountpoint, MINI + "/sub/holes-renamed.bin@0") == HOLES_V0
            assert read_file(mountpoint, MINI + "/sub/holes-renamed.bin@1") == HOLES_V1
            assert read_file(mountpoint, MINI + "/sub/holes-renamed.bin@2") == HOLES_V2

    def test_removed_file_is_kept(self, testpcap):
        with mount_pcap(testpcap) as mountpoint:
            assert read_file(mountpoint, MINI + "/gone.txt") == b"gone\n"

    def test_symlink_is_an_empty_metadata_file(self, testpcap):
        with mount_pcap(testpcap, params=["--show-metadata"]) as mountpoint:
            assert read_file(mountpoint, MINI + "/link-to-hello") == b""


class TestNfsControlFile:
    def test_control_file_content(self, testpcap):
        with mount_pcap(testpcap, params=["--show-metadata"]) as mountpoint:
            text = read_file(mountpoint, CONTROL_FILE).decode("utf-8")
            lines = text.splitlines()
            assert len([line for line in lines if line.startswith("[>] ")]) == RPC_CALLS
            assert len([line for line in lines if line.startswith("[<] ")]) == RPC_CALLS
            assert "[>] NULL" in lines
            assert "[<] NULL" in lines
            assert any(
                line.startswith("[>] COMPOUND SEQUENCE, PUTFH, ") for line in lines
            )
            assert 'LINK "hello-link.txt"' in text
            assert 'REMOVE "hello.txt"' in text
            assert "[>] COMPOUND SEQUENCE, PUTFH, DEALLOCATE, GETATTR" in lines
            assert "[>] COMPOUND SEQUENCE, PUTFH, ALLOCATE, GETATTR" in lines
            assert 'RENAME "holes.bin" -> "holes-renamed.bin"' in text
            assert 'CREATE "link-to-hello"' in text
            assert "WRITE offset=0 len=" in text
            assert lines.count("[<] COMPOUND, Error: NFS4ERR_NOENT (LOOKUP)") == 2
            assert text.count("Error") == 2
            assert "[!]" not in text


class TestNfsIndex:
    def test_mount_from_index_is_identical(self, testpcap):
        with index_file() as index:
            with mount_pcap(
                testpcap, inmem=False, params=["-i", index, "--show-metadata"]
            ) as mountpoint:
                fresh = get_nfs_digests(mountpoint)
            assert os.path.getsize(index) > 0
            with mount_pcap(
                testpcap, inmem=False, params=["-i", index, "--show-metadata"]
            ) as mountpoint:
                from_index = get_nfs_digests(mountpoint)
        assert from_index == fresh
        assert CONTROL_FILE in fresh


class TestNfsTimestampModes:
    @pytest.mark.parametrize(
        "params",
        [[], ["--timestamp-mode", "fs"]],
        ids=["hybrid", "fs"],
    )
    def test_hybrid_and_fs_mode_use_server_timestamps(self, testpcap, params):
        with mount_pcap(testpcap, params=params) as mountpoint:
            assert mtime(mountpoint, MINI + "/hello.txt@0") == T_WRITE
            assert mtime(mountpoint, MINI + "/sub/hello-link.txt@1") == T_LINK
            assert mtime(mountpoint, MINI + "/sub/holes-renamed.bin@2") == T_FALLOCATE

    def test_network_mode_uses_packet_timestamps(self, testpcap):
        with mount_pcap(testpcap, params=["--timestamp-mode", "network"]) as mountpoint:
            assert mtime(mountpoint, MINI + "/hello.txt@0") == T_FIRST_READ
            assert mtime(mountpoint, MINI + "/sub/hello-link.txt@1") == T_LINK


class TestNfsSnapshot:
    def test_before_the_hard_link(self, testpcap):
        with mount_pcap(
            testpcap, params=["--show-metadata", "--snapshot", str(T_LINK)]
        ) as mountpoint:
            files = get_nfs_file_list(mountpoint)
            assert MINI + "/hello.txt" in files
            assert MINI + "/holes.bin" in files
            assert not any(f.startswith(MINI + "/sub/") for f in files)
            assert MINI + "/gone.txt" not in files
            assert MINI + "/link-to-hello" not in files
            assert Path(mountpoint, MINI, "sub").is_dir()
            assert read_file(mountpoint, MINI + "/hello.txt") == HELLO_V0
            assert read_file(mountpoint, MINI + "/holes.bin") == HOLES_V0

    def test_after_the_hard_link_and_the_remove(self, testpcap):
        with mount_pcap(
            testpcap, params=["--show-metadata", "--snapshot", str(T_FALLOCATE)]
        ) as mountpoint:
            files = get_nfs_file_list(mountpoint)
            assert MINI + "/hello.txt" not in files
            assert read_file(mountpoint, MINI + "/sub/hello-link.txt") == HELLO_V1
            assert read_file(mountpoint, MINI + "/holes.bin") == HOLES_V0

    def test_after_fallocate_before_the_rename(self, testpcap):
        with mount_pcap(
            testpcap, params=["--show-metadata", "--snapshot", str(T_RENAME)]
        ) as mountpoint:
            files = get_nfs_file_list(mountpoint)
            assert MINI + "/sub/holes-renamed.bin" not in files
            assert read_file(mountpoint, MINI + "/holes.bin") == HOLES_V2

    def test_after_the_rename(self, testpcap):
        with mount_pcap(
            testpcap, params=["--show-metadata", "--snapshot", str(T_GONE)]
        ) as mountpoint:
            files = get_nfs_file_list(mountpoint)
            assert MINI + "/holes.bin" not in files
            assert MINI + "/gone.txt" not in files
            assert MINI + "/link-to-hello" in files
            assert read_file(mountpoint, MINI + "/sub/holes-renamed.bin") == HOLES_V2
            assert read_file(mountpoint, MINI + "/sub/hello-link.txt") == HELLO_V1


class TestNfsSnip:
    def test_only_versions_touched_in_the_interval_are_shown(self, testpcap):
        # the interval covers the write of both files; names are the final ones (holes.bin is renamed later)
        with mount_pcap(
            testpcap, params=["--snip", "{},{}".format(T_WRITE - 6, T_WRITE + 1)]
        ) as mountpoint:
            files = get_nfs_file_list(mountpoint)
            assert sorted(files) == [
                MINI + "/hello.txt@0",
                MINI + "/sub/holes-renamed.bin@0",
            ]
            assert read_file(mountpoint, MINI + "/hello.txt@0") == HELLO_V0
            assert read_file(mountpoint, MINI + "/sub/holes-renamed.bin@0") == HOLES_V0

    def test_interval_of_the_hard_link(self, testpcap):
        with mount_pcap(
            testpcap, params=["--snip", "{},{}".format(T_LINK, T_FALLOCATE)]
        ) as mountpoint:
            files = get_nfs_file_list(mountpoint)
            assert sorted(files) == [
                MINI + "/hello.txt@1",
                MINI + "/sub/hello-link.txt@1",
            ]
            assert read_file(mountpoint, MINI + "/hello.txt@1") == HELLO_V1
            assert read_file(mountpoint, MINI + "/sub/hello-link.txt@1") == HELLO_V1


@contextmanager
def mount_pcap(pcap, inmem=True, params=None):
    params = list(params) if params else list()
    if inmem:
        params.append("-m")
    with tempfile.TemporaryDirectory() as tmpdir:
        cmd = ["pcapfs", *params, pcap, tmpdir]
        print(" ".join(cmd))
        try:
            subprocess.check_call(cmd)
            yield tmpdir
        finally:
            subprocess.check_call(["fusermount3", "-u", tmpdir])


@contextmanager
def index_file():
    index = "".join(random.choice(string.ascii_lowercase) for _ in range(10))
    try:
        yield index
    finally:
        try:
            os.remove(index)
        except FileNotFoundError:
            pass


def get_nfs_file_list(folder):
    files = list()
    for item in Path(folder, "nfs").rglob("*"):
        if item.is_file():
            files.append(str(item.relative_to(folder)))
    return sorted(files)


def get_nfs_digests(folder):
    return {
        f: hashlib.md5(read_file(folder, f)).hexdigest()
        for f in get_nfs_file_list(folder)
    }


def read_file(folder, relpath):
    with open(Path(folder, relpath), "rb") as f:
        return f.read()


def mtime(folder, relpath):
    return int(os.stat(Path(folder, relpath)).st_mtime)


@pytest.fixture
def expected_nfs_files():
    return sorted(
        [
            MINI + "/gone.txt",
            MINI + "/hello.txt@0",
            MINI + "/hello.txt@1",
            MINI + "/sub/hello-link.txt@0",
            MINI + "/sub/hello-link.txt@1",
            MINI + "/sub/holes-renamed.bin@0",
            MINI + "/sub/holes-renamed.bin@1",
            MINI + "/sub/holes-renamed.bin@2",
        ]
    )


@pytest.fixture
def expected_nfs_files_with_metadata(expected_nfs_files):
    return sorted(expected_nfs_files + [CONTROL_FILE, MINI + "/link-to-hello"])
