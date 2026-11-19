# Example capture

`nfs-v4.2.pcap` is a complete NFSv4.2 session (about 12,000 packets, 11.8 MB) between a Linux client (10.200.0.2)
and a Linux server (10.200.0.1), recorded from the mount on. It is not used by the automated tests.

Workload on the client, in the directory `v4.2` of the export:

1. `mkdir dir1/sub manyfiles`; copy `small.txt` and `medium.bin` into `dir1`; read both.
2. Copy `large.bin` (3 MiB) into `dir1/sub`; create `manyfiles/f1.txt` to `f300.txt`; create the symbolic link
   `link-to-small`.
3. Read all three files; list `dir1` and `manyfiles`.
4. Overwrite 8 KiB in the middle of `dir1/medium.bin`.
5. Append to `dir1/small.txt`; `trunc.txt`: copy of `small.txt`, truncated to 0, then overwritten with `medium.bin`.
6. Rename `dir1/sub/large.bin` to `dir1/renamed-large.bin`; `chmod 600 dir1/small.txt`; copy `renamed-large.bin` to
   `copy-of-large.bin` (CLONE); remove `manyfiles/f1.txt`; remove `dir1/sub`.
7. Read `medium.bin`, `copy-of-large.bin` and `trunc.txt` again; list the root.

Mount it with

    pcapfs --show-metadata examples/nfs-v4.2.pcap /path/to/mountpoint

The reconstructed export is below `nfs/10.200.0.1/`, the calls and replies of the connection are in the control file
in `nfs/`. Files that were changed during the session have several versions (`medium.bin@0`, `medium.bin@1`, ...).
