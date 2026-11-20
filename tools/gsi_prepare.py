#!/usr/bin/env python3
"""
Phase 1: Unprivileged AOSP 12 ARM64 GSI Extractor, APEX Flattener & Linker Configurator.

Extracts raw or Android sparse ext4 system.img without root, preserves POSIX UID/GID/mode,
device rdev, SELinux contexts, and Linux capabilities into a compact mmap-ready binary
database (rootfs_meta.db), flattens .apex/.capex payloads into /apex/<name>, generates
static /linkerconfig/ld.config.txt, and runs an ELF64 AArch64 verification gate.

Zero external dependencies (Python 3.9+ stdlib only).
"""

from __future__ import annotations

import argparse
import bisect
import io
import json
import os
import posixpath
import shutil
import stat
import struct
import sys
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO, Dict, Iterator, List, Optional, Tuple


# =============================================================================
# Constants: Android Sparse Image, ext4, xattr, ELF64, VfsMetaDb
# =============================================================================

SPARSE_HEADER_MAGIC = 0xED26FF3A
CHUNK_TYPE_RAW = 0xCAC1
CHUNK_TYPE_FILL = 0xCAC2
CHUNK_TYPE_DONT_CARE = 0xCAC3
CHUNK_TYPE_CRC32 = 0xCAC4

EXT4_SUPER_MAGIC = 0xEF53
EXT4_SUPERBLOCK_OFFSET = 1024
EXT4_ROOT_INO = 2

EXT4_FEATURE_INCOMPAT_FILETYPE = 0x0002
EXT4_FEATURE_INCOMPAT_EXTENTS = 0x0040
EXT4_FEATURE_INCOMPAT_64BIT = 0x0080

EXT4_EXTENTS_FL = 0x00080000
EXT4_EXTENT_MAGIC = 0xF30A

EXT4_XATTR_MAGIC = 0xEA020000
EXT4_XATTR_PREFIXES = {
    1: "user.",
    2: "system.posix_acl_access",
    3: "system.posix_acl_default",
    4: "trusted.",
    6: "security.",
    7: "system.",
    8: "system.richacl",
}

# VFS Metadata Binary DB Constants (must match vfs_meta_format.hpp)
VMDB_MAGIC = b"VMDB"
VMDB_VERSION = 1
VMDB_HEADER_SIZE = 64
VMDB_ENTRY_SIZE = 48

VMDB_FLAG_IS_DEV_NODE = 1 << 0
VMDB_FLAG_HAS_CAPS = 1 << 1
VMDB_FLAG_FROM_APEX = 1 << 2


def fnv1a_64(data: bytes) -> int:
    """64-bit FNV-1a hash matching vfs_meta_format.hpp."""
    h = 0xCBF29CE484222325
    for b in data:
        h ^= b
        h = (h * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h


# =============================================================================
# 1. Android Sparse Image Random-Access Reader
# =============================================================================

@dataclass(frozen=True)
class SparseChunk:
    out_start: int
    out_end: int
    chunk_type: int
    file_offset: int
    fill_val: bytes


class BlockImageReader:
    """Unified random-access reader for raw ext4 and Android sparse images."""

    def __init__(self, fp: BinaryIO):
        self.fp = fp
        self.fp.seek(0, os.SEEK_END)
        self.raw_file_size = self.fp.tell()
        self.fp.seek(0)

        magic_bytes = self.fp.read(4)
        self.is_sparse = (
            len(magic_bytes) == 4
            and struct.unpack("<I", magic_bytes)[0] == SPARSE_HEADER_MAGIC
        )
        self.chunks: List[SparseChunk] = []
        self.chunk_starts: List[int] = []
        self.virtual_size = self.raw_file_size

        if self.is_sparse:
            self._parse_sparse_header()

    def _parse_sparse_header(self) -> None:
        self.fp.seek(0)
        hdr = self.fp.read(28)
        if len(hdr) < 28:
            raise ValueError("Truncated Android sparse header")
        (
            magic,
            major_ver,
            minor_ver,
            file_hdr_sz,
            chunk_hdr_sz,
            blk_sz,
            total_blks,
            total_chunks,
            _checksum,
        ) = struct.unpack("<IHHHHIIII", hdr)
        if magic != SPARSE_HEADER_MAGIC or major_ver != 1:
            raise ValueError(f"Unsupported sparse image version {major_ver}.{minor_ver}")

        self.virtual_size = blk_sz * total_blks
        pos = file_hdr_sz
        out_off = 0

        for _ in range(total_chunks):
            self.fp.seek(pos)
            chdr = self.fp.read(12)
            if len(chdr) < 12:
                raise ValueError("Truncated sparse chunk header")
            chunk_type, _reserved, chunk_sz_blks, total_sz = struct.unpack("<HHII", chdr)
            data_pos = pos + chunk_hdr_sz
            out_len = chunk_sz_blks * blk_sz

            fill_val = b"\x00\x00\x00\x00"
            if chunk_type == CHUNK_TYPE_FILL:
                self.fp.seek(data_pos)
                fill_val = self.fp.read(4)

            if out_len > 0 and chunk_type in (
                CHUNK_TYPE_RAW,
                CHUNK_TYPE_FILL,
                CHUNK_TYPE_DONT_CARE,
            ):
                self.chunks.append(
                    SparseChunk(out_off, out_off + out_len, chunk_type, data_pos, fill_val)
                )
                self.chunk_starts.append(out_off)
                out_off += out_len

            pos += total_sz

    def pread(self, offset: int, length: int) -> bytes:
        if length <= 0 or offset >= self.virtual_size:
            return b""
        if not self.is_sparse:
            self.fp.seek(offset)
            return self.fp.read(length)

        end = min(offset + length, self.virtual_size)
        out = bytearray()
        cur = offset
        idx = bisect.bisect_right(self.chunk_starts, cur) - 1

        while cur < end and 0 <= idx < len(self.chunks):
            chunk = self.chunks[idx]
            if cur >= chunk.out_end:
                idx += 1
                continue
            take = min(end, chunk.out_end) - cur
            rel = cur - chunk.out_start
            if chunk.chunk_type == CHUNK_TYPE_RAW:
                self.fp.seek(chunk.file_offset + rel)
                data = self.fp.read(take)
                if len(data) < take:
                    data += b"\x00" * (take - len(data))
                out.extend(data)
            elif chunk.chunk_type == CHUNK_TYPE_DONT_CARE:
                out.extend(b"\x00" * take)
            elif chunk.chunk_type == CHUNK_TYPE_FILL:
                pat = chunk.fill_val
                if pat == b"\x00\x00\x00\x00":
                    out.extend(b"\x00" * take)
                else:
                    # Handle unaligned start into 4-byte fill pattern
                    shift = rel % 4
                    rotated = pat[shift:] + pat[:shift]
                    reps = (take // 4) + 1
                    out.extend((rotated * reps)[:take])
            cur += take
            if cur >= chunk.out_end:
                idx += 1

        if len(out) < (end - offset):
            out.extend(b"\x00" * ((end - offset) - len(out)))
        return bytes(out)


# =============================================================================
# 2. Pure-Python Unprivileged ext4 Reader
# =============================================================================

@dataclass
class Ext4Inode:
    ino: int
    mode: int
    uid: int
    gid: int
    size: int
    flags: int
    i_block: bytes
    file_acl: int
    extra_isize: int
    raw_extra: bytes
    xattrs: Dict[str, bytes] = field(default_factory=dict)

    @property
    def is_dir(self) -> bool:
        return stat.S_ISDIR(self.mode)

    @property
    def is_reg(self) -> bool:
        return stat.S_ISREG(self.mode)

    @property
    def is_lnk(self) -> bool:
        return stat.S_ISLNK(self.mode)

    @property
    def is_dev(self) -> bool:
        return stat.S_ISCHR(self.mode) or stat.S_ISBLK(self.mode)

    @property
    def rdev(self) -> int:
        if not self.is_dev:
            return 0
        # Linux ext4 stores old rdev in i_block[0] or new rdev in i_block[1]
        b0, b1 = struct.unpack_from("<II", self.i_block, 0)
        return b0 if b0 != 0 else b1


class Ext4Reader:
    """Read-only user-space ext4 parser supporting 64-bit, extents, indirect blocks, and xattrs."""

    def __init__(self, img: BlockImageReader):
        self.img = img
        sb = self.img.pread(EXT4_SUPERBLOCK_OFFSET, 1024)
        if len(sb) < 256:
            raise ValueError("Image too small to contain ext4 superblock")

        (
            self.inodes_count,
            blocks_count_lo,
            _r_blocks_lo,
            _free_blocks_lo,
            _free_inodes,
            self.first_data_block,
            log_block_size,
            _log_cluster_size,
            self.blocks_per_group,
            _clusters_per_group,
            self.inodes_per_group,
        ) = struct.unpack_from("<11I", sb, 0)

        magic = struct.unpack_from("<H", sb, 0x38)[0]
        if magic != EXT4_SUPER_MAGIC:
            raise ValueError(f"Invalid ext4 superblock magic: 0x{magic:04x}")

        self.block_size = 1024 << log_block_size
        self.inode_size = struct.unpack_from("<H", sb, 0x58)[0] or 128
        self.feature_incompat = struct.unpack_from("<I", sb, 0x60)[0]
        self.is_64bit = bool(self.feature_incompat & EXT4_FEATURE_INCOMPAT_64BIT)
        desc_size_field = struct.unpack_from("<H", sb, 0xFE)[0]
        self.desc_size = desc_size_field if (self.is_64bit and desc_size_field >= 64) else 32

        blocks_count_hi = struct.unpack_from("<I", sb, 0x150)[0] if self.is_64bit else 0
        self.blocks_count = blocks_count_lo | (blocks_count_hi << 32)
        self.num_groups = (self.inodes_count + self.inodes_per_group - 1) // self.inodes_per_group

        # Group descriptor table starts in the block immediately following the superblock
        gdt_block = 2 if self.block_size == 1024 else 1
        self.gdt_offset = gdt_block * self.block_size
        self._inode_table_blocks: List[int] = self._read_group_descriptors()

    def _read_group_descriptors(self) -> List[int]:
        raw = self.img.pread(self.gdt_offset, self.num_groups * self.desc_size)
        tables: List[int] = []
        for g in range(self.num_groups):
            off = g * self.desc_size
            lo = struct.unpack_from("<I", raw, off + 8)[0]
            hi = struct.unpack_from("<I", raw, off + 40)[0] if self.desc_size >= 64 else 0
            tables.append(lo | (hi << 32))
        return tables

    def read_block(self, blk_no: int) -> bytes:
        if blk_no == 0:
            return b"\x00" * self.block_size
        return self.img.pread(blk_no * self.block_size, self.block_size)

    def read_inode(self, ino: int) -> Ext4Inode:
        if ino < 1 or ino > self.inodes_count:
            raise ValueError(f"Inode out of range: {ino}")
        group = (ino - 1) // self.inodes_per_group
        index = (ino - 1) % self.inodes_per_group
        table_off = self._inode_table_blocks[group] * self.block_size
        raw = self.img.pread(table_off + index * self.inode_size, self.inode_size)

        mode, uid_lo, size_lo = struct.unpack_from("<HHI", raw, 0x00)
        gid_lo = struct.unpack_from("<H", raw, 0x18)[0]
        flags = struct.unpack_from("<I", raw, 0x20)[0]
        i_block = raw[0x28:0x64]
        file_acl_lo = struct.unpack_from("<I", raw, 0x68)[0]
        size_hi = struct.unpack_from("<I", raw, 0x6C)[0]
        # Linux OSD2 fields at 0x74..0x7F
        file_acl_hi, uid_hi, gid_hi = struct.unpack_from("<HxxHH", raw, 0x74)

        uid = uid_lo | (uid_hi << 16)
        gid = gid_lo | (gid_hi << 16)
        size = size_lo | (size_hi << 32) if stat.S_ISREG(mode) else size_lo
        file_acl = file_acl_lo | (file_acl_hi << 32)

        extra_isize = 0
        raw_extra = b""
        if self.inode_size > 128:
            extra_isize = struct.unpack_from("<H", raw, 0x80)[0]
            if 128 + extra_isize < len(raw):
                raw_extra = raw[128 + extra_isize :]

        inode = Ext4Inode(
            ino=ino,
            mode=mode,
            uid=uid,
            gid=gid,
            size=size,
            flags=flags,
            i_block=i_block,
            file_acl=file_acl,
            extra_isize=extra_isize,
            raw_extra=raw_extra,
        )
        self._parse_xattrs(inode)
        return inode

    def _parse_xattr_region(self, buf: bytes, entry_start: int, value_base: int, out: Dict[str, bytes]) -> None:
        pos = entry_start
        while pos + 16 <= len(buf):
            name_len, name_idx, val_offs, _val_inum, val_size = struct.unpack_from(
                "<BBHII", buf, pos
            )
            if name_len == 0 and name_idx == 0 and val_offs == 0:
                break
            name_bytes = buf[pos + 16 : pos + 16 + name_len]
            prefix = EXT4_XATTR_PREFIXES.get(name_idx, f"idx{name_idx}.")
            full_name = prefix + name_bytes.decode("utf-8", errors="replace")
            vstart = value_base + val_offs
            if val_size == 0:
                out[full_name] = b""
            elif vstart + val_size <= len(buf):
                out[full_name] = buf[vstart : vstart + val_size]
            # Entries are 4-byte aligned
            step = (16 + name_len + 3) & ~3
            pos += step

    def _parse_xattrs(self, inode: Ext4Inode) -> None:
        # 1. Inline xattrs inside the inode
        if len(inode.raw_extra) >= 4:
            magic = struct.unpack_from("<I", inode.raw_extra, 0)[0]
            if magic == EXT4_XATTR_MAGIC:
                self._parse_xattr_region(inode.raw_extra, 4, 4, inode.xattrs)
        # 2. External xattr block
        if inode.file_acl:
            blk = self.read_block(inode.file_acl)
            if len(blk) >= 32 and struct.unpack_from("<I", blk, 0)[0] == EXT4_XATTR_MAGIC:
                self._parse_xattr_region(blk, 32, 0, inode.xattrs)

    def _iter_extent_runs(self, node_bytes: bytes) -> Iterator[Tuple[int, int, int]]:
        """Yields (logical_block, physical_block, block_count). physical_block==0 means sparse."""
        magic, entries, _max, depth = struct.unpack_from("<HHHH", node_bytes, 0)
        if magic != EXT4_EXTENT_MAGIC:
            raise ValueError(f"Corrupt ext4 extent header magic: 0x{magic:04x}")
        if depth == 0:
            for i in range(entries):
                off = 12 + i * 12
                ee_block, ee_len, ee_start_hi, ee_start_lo = struct.unpack_from("<IHHI", node_bytes, off)
                unwritten = ee_len > 32768
                real_len = ee_len - 32768 if unwritten else ee_len
                phys = 0 if unwritten else (ee_start_lo | (ee_start_hi << 32))
                yield (ee_block, phys, real_len)
        else:
            for i in range(entries):
                off = 12 + i * 12
                _ei_block, ei_leaf_lo, ei_leaf_hi = struct.unpack_from("<IIH", node_bytes, off)
                child_blk = ei_leaf_lo | (ei_leaf_hi << 32)
                child_data = self.read_block(child_blk)
                yield from self._iter_extent_runs(child_data)

    def _iter_indirect_blocks(self, blk_no: int, level: int) -> Iterator[int]:
        if blk_no == 0:
            ptrs_per_blk = self.block_size // 4
            yield from (0 for _ in range(ptrs_per_blk ** level))
            return
        data = self.read_block(blk_no)
        ptrs = struct.unpack(f"<{self.block_size // 4}I", data)
        if level == 1:
            yield from ptrs
        else:
            for p in ptrs:
                yield from self._iter_indirect_blocks(p, level - 1)

    def iter_file_chunks(self, inode: Ext4Inode) -> Iterator[bytes]:
        """Streams file contents without loading large files entirely into RAM."""
        remaining = inode.size
        if remaining == 0:
            return

        if inode.flags & EXT4_EXTENTS_FL:
            cur_lblock = 0
            for lblock, pblock, count in self._iter_extent_runs(inode.i_block):
                if remaining <= 0:
                    break
                if lblock > cur_lblock:
                    gap_bytes = min((lblock - cur_lblock) * self.block_size, remaining)
                    yield b"\x00" * gap_bytes
                    remaining -= gap_bytes
                    cur_lblock = lblock
                if remaining <= 0:
                    break
                run_bytes = min(count * self.block_size, remaining)
                if pblock == 0:
                    yield b"\x00" * run_bytes
                else:
                    # Read in <= 1 MiB slices to keep memory flat
                    slice_sz = 1024 * 1024
                    off = pblock * self.block_size
                    left = run_bytes
                    while left > 0:
                        chunk_len = min(left, slice_sz)
                        yield self.img.pread(off, chunk_len)
                        off += chunk_len
                        left -= chunk_len
                remaining -= run_bytes
                cur_lblock += count
            if remaining > 0:
                yield b"\x00" * remaining
        else:
            ptrs = struct.unpack_from("<15I", inode.i_block, 0)
            def all_blocks() -> Iterator[int]:
                for b in ptrs[:12]:
                    yield b
                if ptrs[12]:
                    yield from self._iter_indirect_blocks(ptrs[12], 1)
                if ptrs[13]:
                    yield from self._iter_indirect_blocks(ptrs[13], 2)
                if ptrs[14]:
                    yield from self._iter_indirect_blocks(ptrs[14], 3)

            for pblk in all_blocks():
                if remaining <= 0:
                    break
                take = min(self.block_size, remaining)
                data = self.read_block(pblk)[:take]
                yield data
                remaining -= take

    def read_file_bytes(self, inode: Ext4Inode) -> bytes:
        return b"".join(self.iter_file_chunks(inode))

    def read_symlink(self, inode: Ext4Inode) -> str:
        # Fast symlink stored inline in i_block when size <= 60 and no blocks allocated
        if inode.size <= 60 and not (inode.flags & EXT4_EXTENTS_FL):
            return inode.i_block[: inode.size].decode("utf-8", errors="surrogateescape")
        return self.read_file_bytes(inode).decode("utf-8", errors="surrogateescape")

    def iter_dir_entries(self, inode: Ext4Inode) -> Iterator[Tuple[str, int]]:
        data = self.read_file_bytes(inode)
        pos = 0
        total = len(data)
        while pos + 8 <= total:
            child_ino, rec_len, name_len, _file_type = struct.unpack_from("<IHBB", data, pos)
            if rec_len == 0:
                break
            if child_ino != 0 and name_len > 0:
                name = data[pos + 8 : pos + 8 + name_len].decode("utf-8", errors="surrogateescape")
                if name not in (".", ".."):
                    yield name, child_ino
            pos += rec_len


# =============================================================================
# 3. VFS Metadata Collector & Binary DB Writer (rootfs_meta.db)
# =============================================================================

@dataclass
class MetaRecord:
    guest_path: str
    uid: int
    gid: int
    mode: int
    rdev: int
    selinux: str
    caps_lo: int
    caps_hi: int
    flags: int


def parse_vfs_caps(raw: Optional[bytes]) -> Tuple[int, int, bool]:
    """Extracts effective/permitted capability bits from security.capability xattr."""
    if not raw or len(raw) < 12:
        return 0, 0, False
    magic_etc = struct.unpack_from("<I", raw, 0)[0]
    ver = (magic_etc >> 24) & 0xFF
    if ver == 1 and len(raw) >= 12:
        perm_lo = struct.unpack_from("<I", raw, 4)[0]
        return perm_lo, 0, True
    if ver in (2, 3) and len(raw) >= 20:
        perm_lo = struct.unpack_from("<I", raw, 4)[0]
        perm_hi = struct.unpack_from("<I", raw, 12)[0]
        return perm_lo, perm_hi, True
    return 0, 0, False


class MetadataStore:
    def __init__(self) -> None:
        self.records: Dict[str, MetaRecord] = {}

    def add_inode(self, guest_path: str, inode: Ext4Inode, from_apex: bool = False) -> None:
        canon = posixpath.normpath(guest_path)
        if not canon.startswith("/"):
            canon = "/" + canon
        selinux_raw = inode.xattrs.get("security.selinux", b"")
        selinux = selinux_raw.rstrip(b"\x00").decode("utf-8", errors="replace")
        caps_lo, caps_hi, has_caps = parse_vfs_caps(inode.xattrs.get("security.capability"))

        flags = 0
        if inode.is_dev:
            flags |= VMDB_FLAG_IS_DEV_NODE
        if has_caps:
            flags |= VMDB_FLAG_HAS_CAPS
        if from_apex:
            flags |= VMDB_FLAG_FROM_APEX

        self.records[canon] = MetaRecord(
            guest_path=canon,
            uid=inode.uid,
            gid=inode.gid,
            mode=inode.mode,
            rdev=inode.rdev,
            selinux=selinux,
            caps_lo=caps_lo,
            caps_hi=caps_hi,
            flags=flags,
        )

    def add_synthetic(
        self,
        guest_path: str,
        uid: int,
        gid: int,
        mode: int,
        selinux: str = "u:object_r:system_file:s0",
        rdev: int = 0,
        flags: int = 0,
    ) -> None:
        canon = posixpath.normpath(guest_path)
        if not canon.startswith("/"):
            canon = "/" + canon
        self.records[canon] = MetaRecord(
            guest_path=canon,
            uid=uid,
            gid=gid,
            mode=mode,
            rdev=rdev,
            selinux=selinux,
            caps_lo=0,
            caps_hi=0,
            flags=flags,
        )

    def write_binary_db(self, out_path: Path) -> int:
        """Writes sorted mmap-ready binary DB matching vfs_meta_format.hpp."""
        entries_with_hash: List[Tuple[int, MetaRecord]] = []
        for path, rec in self.records.items():
            entries_with_hash.append((fnv1a_64(path.encode("utf-8")), rec))
        entries_with_hash.sort(key=lambda item: (item[0], item[1].guest_path))

        string_pool = bytearray()
        string_cache: Dict[bytes, int] = {}

        def intern(s: str) -> Tuple[int, int]:
            b = s.encode("utf-8")
            if b in string_cache:
                return string_cache[b], len(b)
            off = len(string_pool)
            string_pool.extend(b)
            string_pool.append(0)
            string_cache[b] = off
            return off, len(b)

        entry_buf = bytearray()
        for h, rec in entries_with_hash:
            p_off, p_len = intern(rec.guest_path)
            s_off, s_len = intern(rec.selinux)
            entry_buf.extend(
                struct.pack(
                    "<QIHHI7I",
                    h,
                    p_off,
                    p_len,
                    s_len,
                    s_off,
                    rec.uid,
                    rec.gid,
                    rec.mode,
                    rec.rdev,
                    rec.caps_lo,
                    rec.caps_hi,
                    rec.flags,
                )
            )

        entry_table_off = VMDB_HEADER_SIZE
        string_table_off = entry_table_off + len(entry_buf)
        total_size = string_table_off + len(string_pool)

        header = struct.pack(
            "<4sIIIIQQQ20x",
            VMDB_MAGIC,
            VMDB_VERSION,
            VMDB_ENTRY_SIZE,
            0,
            len(entries_with_hash),
            entry_table_off,
            string_table_off,
            total_size,
        )
        assert len(header) == VMDB_HEADER_SIZE

        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "wb") as f:
            f.write(header)
            f.write(entry_buf)
            f.write(string_pool)
        return len(entries_with_hash)


# =============================================================================
# 4. Extraction Engine & Minimal Protobuf Manifest Parser for APEX
# =============================================================================

def extract_ext4_tree(
    reader: Ext4Reader,
    dest_dir: Path,
    guest_prefix: str,
    meta: MetadataStore,
    from_apex: bool = False,
) -> Dict[str, int]:
    """Unpacks an entire ext4 filesystem into dest_dir without root privileges."""
    stats = {"dirs": 0, "files": 0, "symlinks": 0, "devs_virtualized": 0}
    dest_dir.mkdir(parents=True, exist_ok=True)

    root_inode = reader.read_inode(EXT4_ROOT_INO)
    meta.add_inode(guest_prefix, root_inode, from_apex=from_apex)

    # Iterative DFS to avoid recursion limits on deep trees
    stack: List[Tuple[int, Path, str]] = [(EXT4_ROOT_INO, dest_dir, guest_prefix)]
    visited_dirs = {EXT4_ROOT_INO}

    while stack:
        dir_ino, host_dir, g_dir = stack.pop()
        dir_inode = reader.read_inode(dir_ino)
        for name, child_ino in reader.iter_dir_entries(dir_inode):
            if name == "lost+found" and dir_ino == EXT4_ROOT_INO:
                continue
            child = reader.read_inode(child_ino)
            host_path = host_dir / name
            guest_path = posixpath.join(g_dir, name)
            meta.add_inode(guest_path, child, from_apex=from_apex)

            if child.is_dir:
                host_path.mkdir(parents=True, exist_ok=True)
                os.chmod(host_path, 0o755)
                stats["dirs"] += 1
                if child_ino not in visited_dirs:
                    visited_dirs.add(child_ino)
                    stack.append((child_ino, host_path, guest_path))
            elif child.is_lnk:
                target = reader.read_symlink(child)
                if host_path.exists() or host_path.is_symlink():
                    host_path.unlink()
                os.symlink(target, host_path)
                stats["symlinks"] += 1
            elif child.is_reg:
                if host_path.is_symlink():
                    host_path.unlink()
                with open(host_path, "wb") as out_f:
                    for chunk in reader.iter_file_chunks(child):
                        out_f.write(chunk)
                # Keep binaries executable on host (targetSdkVersion 28) & writable for cleanup
                exec_bits = 0o111 if (child.mode & 0o111) else 0
                os.chmod(host_path, 0o644 | exec_bits)
                stats["files"] += 1
            elif child.is_dev:
                # Never call mknod() unprivileged; Phase 2 virtualizes via rootfs_meta.db
                stats["devs_virtualized"] += 1

    return stats


def _read_varint(buf: bytes, pos: int) -> Tuple[int, int]:
    result = 0
    shift = 0
    while pos < len(buf):
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, pos
        shift += 7
    raise ValueError("Truncated protobuf varint")


def parse_apex_manifest_pb(data: bytes) -> Tuple[str, int]:
    """Minimal protobuf wire decoder for ApexManifest { string name = 1; int64 version = 2; }."""
    name = ""
    version = 1
    pos = 0
    n = len(data)
    while pos < n:
        tag, pos = _read_varint(data, pos)
        field_num = tag >> 3
        wire_type = tag & 0x7
        if wire_type == 0:  # varint
            val, pos = _read_varint(data, pos)
            if field_num == 2:
                version = val
        elif wire_type == 2:  # length-delimited
            length, pos = _read_varint(data, pos)
            val_bytes = data[pos : pos + length]
            pos += length
            if field_num == 1:
                name = val_bytes.decode("utf-8", errors="replace")
        elif wire_type == 1:  # 64-bit
            pos += 8
        elif wire_type == 5:  # 32-bit
            pos += 4
        else:
            break
    if not name:
        raise ValueError("apex_manifest.pb missing required 'name' field")
    return name, version


def read_apex_manifest(zf: zipfile.ZipFile) -> Tuple[str, int]:
    names = set(zf.namelist())
    if "apex_manifest.json" in names:
        obj = json.loads(zf.read("apex_manifest.json").decode("utf-8"))
        return str(obj["name"]), int(obj.get("version", 1))
    if "apex_manifest.pb" in names:
        return parse_apex_manifest_pb(zf.read("apex_manifest.pb"))
    raise ValueError("APEX archive lacks apex_manifest.json and apex_manifest.pb")


def flatten_apex_archive(
    archive_path: Path, apex_root: Path, meta: MetadataStore
) -> Tuple[str, int]:
    """Unpacks a .apex or .capex into rootfs/apex/<name>/ and symlinks <name>@<version>."""
    with tempfile.TemporaryDirectory(prefix="apex_unpack_") as tmp:
        tmp_dir = Path(tmp)
        active_zip_path = archive_path

        # Handle .capex (compressed APEX wrapping original_apex)
        if archive_path.suffix == ".capex":
            with zipfile.ZipFile(archive_path, "r") as czf:
                if "original_apex" not in czf.namelist():
                    raise ValueError(f"{archive_path.name} missing original_apex")
                extracted_apex = tmp_dir / "original_apex.apex"
                with czf.open("original_apex") as src, open(extracted_apex, "wb") as dst:
                    shutil.copyfileobj(src, dst)
                active_zip_path = extracted_apex

        with zipfile.ZipFile(active_zip_path, "r") as zf:
            mod_name, mod_version = read_apex_manifest(zf)
            if "apex_payload.img" not in zf.namelist():
                raise ValueError(f"{archive_path.name} ({mod_name}) missing apex_payload.img")

            payload_path = tmp_dir / "apex_payload.img"
            with zf.open("apex_payload.img") as src, open(payload_path, "wb") as dst:
                shutil.copyfileobj(src, dst)

        dest_mod = apex_root / mod_name
        if dest_mod.exists():
            shutil.rmtree(dest_mod)

        with open(payload_path, "rb") as pf:
            img = BlockImageReader(pf)
            ext4 = Ext4Reader(img)
            extract_ext4_tree(
                ext4, dest_mod, f"/apex/{mod_name}", meta, from_apex=True
            )

        ver_link = apex_root / f"{mod_name}@{mod_version}"
        if ver_link.exists() or ver_link.is_symlink():
            ver_link.unlink()
        os.symlink(mod_name, ver_link)
        meta.add_synthetic(
            f"/apex/{mod_name}@{mod_version}",
            uid=0,
            gid=0,
            mode=stat.S_IFLNK | 0o777,
            selinux="u:object_r:apex_mnt_dir:s0",
            flags=VMDB_FLAG_FROM_APEX,
        )
        return mod_name, mod_version


def flatten_all_apexes(rootfs: Path, meta: MetadataStore) -> List[Tuple[str, int]]:
    apex_root = rootfs / "apex"
    apex_root.mkdir(parents=True, exist_ok=True)
    meta.add_synthetic("/apex", 0, 0, stat.S_IFDIR | 0o755, "u:object_r:apex_mnt_dir:s0")

    discovered: List[Tuple[str, int]] = []
    search_dirs = [
        rootfs / "system" / "apex",
        rootfs / "system_ext" / "apex",
        rootfs / "vendor" / "apex",
    ]

    for sdir in search_dirs:
        if not sdir.is_dir():
            continue
        for item in sorted(sdir.iterdir()):
            if item.is_file() and item.suffix in (".apex", ".capex"):
                mod_name, mod_ver = flatten_apex_archive(item, apex_root, meta)
                discovered.append((mod_name, mod_ver))
            elif item.is_dir():
                # Handle GSIs that already ship pre-flattened directories under /system/apex
                manifest_json = item / "apex_manifest.json"
                manifest_pb = item / "apex_manifest.pb"
                mod_name = item.name
                mod_ver = 1
                if manifest_json.is_file():
                    obj = json.loads(manifest_json.read_text(encoding="utf-8"))
                    mod_name = str(obj.get("name", mod_name))
                    mod_ver = int(obj.get("version", 1))
                elif manifest_pb.is_file():
                    mod_name, mod_ver = parse_apex_manifest_pb(manifest_pb.read_bytes())

                dest_mod = apex_root / mod_name
                if dest_mod.exists():
                    shutil.rmtree(dest_mod)
                shutil.copytree(item, dest_mod, symlinks=True)
                ver_link = apex_root / f"{mod_name}@{mod_ver}"
                if ver_link.exists() or ver_link.is_symlink():
                    ver_link.unlink()
                os.symlink(mod_name, ver_link)
                discovered.append((mod_name, mod_ver))

    return discovered


# =============================================================================
# 5. Static Android 12 Linker Namespace Configuration & Runtime Skeleton
# =============================================================================

def generate_linker_config(rootfs: Path, apex_modules: List[Tuple[str, int]], meta: MetadataStore) -> Path:
    """Generates /linkerconfig/ld.config.txt so linker64 resolves flattened /apex libs."""
    apex_names = sorted({name for name, _ in apex_modules})
    apex_lib_paths = [f"/apex/{name}/lib64" for name in apex_names]
    default_search = [
        "/system/lib64",
        "/system_ext/lib64",
        "/product/lib64",
        "/vendor/lib64",
        "/vendor/lib64/hw",
    ] + apex_lib_paths

    lines: List[str] = [
        "# Auto-generated by gsi_prepare.py for unrooted AOSP 12 flattened APEX container",
        "dir.system = /system/bin/",
        "dir.system = /system/xbin/",
        "dir.system = /system_ext/bin/",
        "dir.system = /product/bin/",
        "dir.vendor = /vendor/bin/",
    ]
    for name in apex_names:
        ns = name.replace(".", "_")
        lines.append(f"dir.{ns} = /apex/{name}/bin/")

    # Unified [system] section with full visibility across flattened APEX modules
    ns_list = ["sphal", "vndk"] + [n.replace(".", "_") for n in apex_names]
    lines += [
        "",
        "[system]",
        f"additional.namespaces = {','.join(ns_list)}",
        "",
        "namespace.default.isolated = false",
        f"namespace.default.search.paths = {':'.join(default_search)}",
        "namespace.default.permitted.paths = /system:/system_ext:/product:/vendor:/apex:/data",
    ]
    if ns_list:
        lines.append(f"namespace.default.links = {','.join(ns_list)}")
    for ns in ns_list:
        lines.append(f"namespace.default.link.{ns}.allow_all_shared_libs = true")

    lines += [
        "",
        "namespace.sphal.isolated = false",
        "namespace.sphal.search.paths = /vendor/lib64:/vendor/lib64/hw:/system/lib64",
        "namespace.sphal.permitted.paths = /vendor:/system:/apex:/data",
        "namespace.sphal.links = default",
        "namespace.sphal.link.default.allow_all_shared_libs = true",
        "",
        "namespace.vndk.isolated = false",
        "namespace.vndk.search.paths = /system/lib64/vndk-sp-31:/system/lib64/vndk-31:/system/lib64",
        "namespace.vndk.permitted.paths = /system:/vendor:/apex",
        "namespace.vndk.links = default",
        "namespace.vndk.link.default.allow_all_shared_libs = true",
    ]

    for name in apex_names:
        ns = name.replace(".", "_")
        lines += [
            "",
            f"namespace.{ns}.isolated = false",
            f"namespace.{ns}.search.paths = /apex/{name}/lib64:/system/lib64",
            f"namespace.{ns}.permitted.paths = /apex/{name}:/system:/data:/vendor",
            f"namespace.{ns}.links = default",
            f"namespace.{ns}.link.default.allow_all_shared_libs = true",
        ]

    # Vendor section shares same permissive search paths for our virtual HALs
    lines += [
        "",
        "[vendor]",
        "namespace.default.isolated = false",
        f"namespace.default.search.paths = /vendor/lib64:/vendor/lib64/hw:{':'.join(default_search)}",
        "namespace.default.permitted.paths = /vendor:/system:/apex:/data",
    ]

    for name in apex_names:
        ns = name.replace(".", "_")
        lines += [
            "",
            f"[{ns}]",
            "namespace.default.isolated = false",
            f"namespace.default.search.paths = /apex/{name}/lib64:{':'.join(default_search)}",
            "namespace.default.permitted.paths = /apex:/system:/vendor:/data",
        ]

    ld_dir = rootfs / "linkerconfig"
    ld_dir.mkdir(parents=True, exist_ok=True)
    ld_cfg = ld_dir / "ld.config.txt"
    ld_cfg.write_text("\n".join(lines) + "\n", encoding="utf-8")

    meta.add_synthetic("/linkerconfig", 0, 0, stat.S_IFDIR | 0o755)
    meta.add_synthetic("/linkerconfig/ld.config.txt", 0, 0, stat.S_IFREG | 0o644)
    return ld_cfg


def prepare_runtime_skeleton(rootfs: Path, meta: MetadataStore) -> None:
    """Creates mandatory guest mountpoint/runtime directories and ensures linker64 link."""
    dirs_spec = [
        ("/data", 1000, 1000, 0o771, "u:object_r:system_data_file:s0"),
        ("/data/app", 1000, 1000, 0o771, "u:object_r:apk_data_file:s0"),
        ("/data/data", 1000, 1000, 0o771, "u:object_r:system_data_file:s0"),
        ("/data/user", 1000, 1000, 0o771, "u:object_r:system_data_file:s0"),
        ("/data/user/0", 1000, 1000, 0o771, "u:object_r:system_data_file:s0"),
        ("/data/dalvik-cache", 0, 0, 0o771, "u:object_r:dalvikcache_data_file:s0"),
        ("/data/dalvik-cache/arm64", 0, 0, 0o771, "u:object_r:dalvikcache_data_file:s0"),
        ("/data/system", 1000, 1000, 0o775, "u:object_r:system_data_file:s0"),
        ("/data/misc", 1000, 9998, 0o1771, "u:object_r:system_data_file:s0"),
        ("/data/local", 2000, 2000, 0o751, "u:object_r:shell_data_file:s0"),
        ("/data/local/tmp", 2000, 2000, 0o771, "u:object_r:shell_data_file:s0"),
        ("/dev", 0, 0, 0o755, "u:object_r:device:s0"),
        ("/dev/socket", 0, 0, 0o755, "u:object_r:socket_device:s0"),
        ("/dev/__properties__", 0, 0, 0o755, "u:object_r:properties_device:s0"),
        ("/dev/input", 0, 0, 0o755, "u:object_r:input_device:s0"),
        ("/proc", 0, 0, 0o555, "u:object_r:proc:s0"),
        ("/sys", 0, 0, 0o555, "u:object_r:sysfs:s0"),
        ("/vendor", 0, 2000, 0o755, "u:object_r:vendor_file:s0"),
        ("/vendor/lib64", 0, 2000, 0o755, "u:object_r:vendor_file:s0"),
        ("/vendor/lib64/hw", 0, 2000, 0o755, "u:object_r:vendor_hal_file:s0"),
        ("/vendor/etc", 0, 2000, 0o755, "u:object_r:vendor_configs_file:s0"),
        ("/vendor/etc/vintf", 0, 2000, 0o755, "u:object_r:vendor_configs_file:s0"),
        ("/tmp", 0, 0, 0o1777, "u:object_r:tmpfs:s0"),
        ("/mnt", 0, 1000, 0o755, "u:object_r:tmpfs:s0"),
        ("/storage", 0, 1028, 0o755, "u:object_r:storage_file:s0"),
    ]
    for gpath, uid, gid, mode, selinux in dirs_spec:
        hpath = rootfs / gpath.lstrip("/")
        hpath.mkdir(parents=True, exist_ok=True)
        if gpath not in meta.records:
            meta.add_synthetic(gpath, uid, gid, stat.S_IFDIR | mode, selinux)

    # Ensure /system/bin/linker64 points into flattened com.android.runtime APEX if present
    apex_linker = rootfs / "apex" / "com.android.runtime" / "bin" / "linker64"
    sys_linker = rootfs / "system" / "bin" / "linker64"
    if apex_linker.is_file() and not sys_linker.exists():
        sys_linker.parent.mkdir(parents=True, exist_ok=True)
        if sys_linker.is_symlink():
            sys_linker.unlink()
        os.symlink("/apex/com.android.runtime/bin/linker64", sys_linker)
        meta.add_synthetic("/system/bin/linker64", 0, 2000, stat.S_IFLNK | 0o777)


# =============================================================================
# 6. Phase 1 Verification Gate: ELF64 AArch64 Interp & DT_NEEDED Audit
# =============================================================================

def parse_elf64_deps(elf_path: Path) -> Tuple[int, Optional[str], List[str]]:
    """Returns (e_machine, pt_interp, dt_needed_list) for an ELF64 binary."""
    data = elf_path.read_bytes()
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[4] != 2:
        raise ValueError(f"{elf_path} is not a 64-bit ELF binary")

    e_machine = struct.unpack_from("<H", data, 18)[0]
    e_phoff = struct.unpack_from("<Q", data, 32)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 54)

    interp: Optional[str] = None
    dyn_off = dyn_sz = 0
    load_segs: List[Tuple[int, int, int]] = []  # (vaddr, filesz, offset)

    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, _p_flags, p_offset, p_vaddr, _p_paddr, p_filesz, _p_memsz, _p_align = (
            struct.unpack_from("<IIQQQQQQ", data, off)
        )
        if p_type == 3:  # PT_INTERP
            interp = data[p_offset : p_offset + p_filesz].rstrip(b"\x00").decode("utf-8")
        elif p_type == 2:  # PT_DYNAMIC
            dyn_off, dyn_sz = p_offset, p_filesz
        elif p_type == 1:  # PT_LOAD
            load_segs.append((p_vaddr, p_filesz, p_offset))

    def vaddr_to_off(vaddr: int) -> Optional[int]:
        for seg_v, seg_fsz, seg_off in load_segs:
            if seg_v <= vaddr < seg_v + seg_fsz:
                return seg_off + (vaddr - seg_v)
        return None

    needed_offsets: List[int] = []
    strtab_vaddr: Optional[int] = None
    strtab_size = 0

    if dyn_off and dyn_sz:
        pos = dyn_off
        end = dyn_off + dyn_sz
        while pos + 16 <= end:
            d_tag, d_val = struct.unpack_from("<qQ", data, pos)
            pos += 16
            if d_tag == 0:  # DT_NULL
                break
            elif d_tag == 1:  # DT_NEEDED
                needed_offsets.append(d_val)
            elif d_tag == 5:  # DT_STRTAB
                strtab_vaddr = d_val
            elif d_tag == 10:  # DT_STRSZ
                strtab_size = d_val

    needed: List[str] = []
    if strtab_vaddr is not None and needed_offsets:
        st_off = vaddr_to_off(strtab_vaddr)
        if st_off is not None:
            strtab = data[st_off : st_off + (strtab_size or len(data) - st_off)]
            for noff in needed_offsets:
                nul = strtab.find(b"\x00", noff)
                name = strtab[noff : nul if nul != -1 else None].decode("utf-8", errors="replace")
                needed.append(name)

    return e_machine, interp, needed


def resolve_guest_path(rootfs: Path, guest_path: str, max_depth: int = 8) -> Optional[Path]:
    """Resolves a guest-absolute path inside rootfs, safely following guest-rooted symlinks."""
    cur = posixpath.normpath(guest_path)
    for _ in range(max_depth):
        host = rootfs / cur.lstrip("/")
        if host.is_symlink():
            target = os.readlink(host)
            if target.startswith("/"):
                cur = posixpath.normpath(target)
            else:
                cur = posixpath.normpath(posixpath.join(posixpath.dirname(cur), target))
            continue
        return host if host.exists() else None
    return None


def verify_rootfs(rootfs: Path, meta_db_path: Path) -> Tuple[bool, List[str]]:
    """Runs Phase 1 verification gate: ELF64 AArch64 deps, linker64, and rootfs_meta.db."""
    issues: List[str] = []

    # 1. Verify rootfs_meta.db header & sort order
    if not meta_db_path.is_file():
        issues.append("Missing rootfs_meta.db")
    else:
        raw = meta_db_path.read_bytes()
        if len(raw) < VMDB_HEADER_SIZE:
            issues.append("rootfs_meta.db truncated")
        else:
            magic, ver, esz, _, count, eoff, soff, tsz = struct.unpack_from("<4sIIIIQQQ", raw, 0)
            if magic != VMDB_MAGIC or ver != VMDB_VERSION or esz != VMDB_ENTRY_SIZE:
                issues.append("rootfs_meta.db header mismatch")
            if tsz != len(raw):
                issues.append(f"rootfs_meta.db size mismatch: header={tsz}, actual={len(raw)}")
            prev_hash = 0
            for i in range(count):
                h = struct.unpack_from("<Q", raw, eoff + i * esz)[0]
                if h < prev_hash:
                    issues.append(f"rootfs_meta.db unsorted at index {i}")
                    break
                prev_hash = h

    # 2. Verify linkerconfig exists
    if not (rootfs / "linkerconfig" / "ld.config.txt").is_file():
        issues.append("Missing /linkerconfig/ld.config.txt")

    # 3. Collect all available shared libraries across /system/lib64, /vendor/lib64, /apex/*/lib64
    lib_dirs = [
        rootfs / "system" / "lib64",
        rootfs / "system_ext" / "lib64",
        rootfs / "vendor" / "lib64",
    ]
    apex_dir = rootfs / "apex"
    if apex_dir.is_dir():
        for entry in apex_dir.iterdir():
            if entry.is_dir() and not entry.is_symlink():
                for sub in ("lib64", "lib64/bionic"):
                    cand = entry / sub
                    if cand.is_dir():
                        lib_dirs.append(cand)

    available_libs = set()
    for ld in lib_dirs:
        if ld.is_dir():
            for f in ld.iterdir():
                available_libs.add(f.name)

    # 4. Inspect core AOSP 12 binaries present in rootfs
    core_bins = [
        "/system/bin/sh",
        "/system/bin/linker64",
        "/system/bin/servicemanager",
        "/system/bin/hwservicemanager",
        "/system/bin/surfaceflinger",
        "/system/bin/app_process64",
    ]
    checked_any = False
    for gbin in core_bins:
        resolved = resolve_guest_path(rootfs, gbin)
        if resolved is None or not resolved.is_file():
            continue
        checked_any = True
        try:
            e_machine, interp, needed = parse_elf64_deps(resolved)
        except Exception as exc:
            issues.append(f"{gbin}: ELF parse failed ({exc})")
            continue
        if e_machine != 183:  # EM_AARCH64
            issues.append(f"{gbin}: non-AArch64 ELF (e_machine={e_machine})")
        if interp:
            interp_host = resolve_guest_path(rootfs, interp)
            if interp_host is None or not interp_host.is_file():
                issues.append(f"{gbin}: unresolved PT_INTERP '{interp}'")
        for lib in needed:
            if lib not in available_libs:
                issues.append(f"{gbin}: missing DT_NEEDED '{lib}'")

    if not checked_any:
        issues.append("No core AOSP binaries found under /system/bin to audit")

    return len(issues) == 0, issues


# =============================================================================
# 7. CLI Entrypoint
# =============================================================================

def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Unprivileged AOSP 12 ARM64 GSI extractor, APEX flattener & linker configurator."
    )
    parser.add_argument("system_img", type=Path, help="Path to AOSP 12 GSI system.img (raw or sparse)")
    parser.add_argument("output_rootfs", type=Path, help="Destination rootfs directory")
    parser.add_argument(
        "--meta-db",
        type=Path,
        default=None,
        help="Output path for binary rootfs_meta.db (default: <output_rootfs>/../rootfs_meta.db)",
    )
    parser.add_argument(
        "--skip-verify", action="store_true", help="Skip Phase 1 ELF64 verification gate"
    )
    args = parser.parse_args(argv)

    rootfs = args.output_rootfs.resolve()
    meta_db = args.meta_db.resolve() if args.meta_db else (rootfs.parent / "rootfs_meta.db")

    if not args.system_img.is_file():
        print(f"[ERROR] Image not found: {args.system_img}", file=sys.stderr)
        return 1

    meta = MetadataStore()

    print(f"[1/5] Opening {args.system_img} ...")
    with open(args.system_img, "rb") as fp:
        img = BlockImageReader(fp)
        fmt = "Android Sparse" if img.is_sparse else "Raw"
        print(f"      Format: {fmt} | Virtual Size: {img.virtual_size / (1024**2):.1f} MiB")
        ext4 = Ext4Reader(img)
        print(
            f"      ext4: block_size={ext4.block_size}, inode_size={ext4.inode_size}, "
            f"inodes={ext4.inodes_count}, 64bit={ext4.is_64bit}"
        )

        print(f"[2/5] Extracting system rootfs -> {rootfs} ...")
        stats = extract_ext4_tree(ext4, rootfs, "/", meta, from_apex=False)
        print(
            f"      Extracted {stats['files']} files, {stats['dirs']} dirs, "
            f"{stats['symlinks']} symlinks, {stats['devs_virtualized']} virtualized dev nodes"
        )

    # Some GSIs mount system at /system inside system.img; others are system-as-root (SAR).
    # Both layouts are preserved natively since AOSP 12 GSIs are system-as-root.
    print("[3/5] Flattening APEX / CAPEX modules ...")
    apex_modules = flatten_all_apexes(rootfs, meta)
    print(f"      Flattened {len(apex_modules)} APEX modules into {rootfs / 'apex'}")

    print("[4/5] Generating /linkerconfig/ld.config.txt & runtime skeleton ...")
    prepare_runtime_skeleton(rootfs, meta)
    ld_cfg = generate_linker_config(rootfs, apex_modules, meta)
    entry_count = meta.write_binary_db(meta_db)
    print(f"      Wrote {ld_cfg}")
    print(f"      Wrote {meta_db} ({entry_count} metadata entries)")

    if not args.skip_verify:
        print("[5/5] Running Phase 1 Verification Gate ...")
        ok, issues = verify_rootfs(rootfs, meta_db)
        if ok:
            print("      [PASS] All audited ELF64 AArch64 binaries, PT_INTERP, DT_NEEDED, and rootfs_meta.db passed.")
            return 0
        print("      [FAIL] Verification issues detected:", file=sys.stderr)
        for iss in issues:
            print(f"        - {iss}", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
