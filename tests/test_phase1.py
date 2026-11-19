#!/usr/bin/env python3
"""Repo-portable CI test suite for Phase 1 (tools/gsi_prepare.py + include/vfs_meta_format.hpp)."""

import os
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
GSI_PREPARE = REPO_ROOT / "tools" / "gsi_prepare.py"
HEADER_DIR = REPO_ROOT / "include"


def make_minimal_aarch64_elf(interp: str | None = None, needed: list[str] | None = None) -> bytes:
    """Constructs a minimal valid ELF64 AArch64 binary with PT_LOAD, optional PT_INTERP and PT_DYNAMIC."""
    needed = needed or []
    phdrs = []
    interp_bytes = (interp.encode("utf-8") + b"\x00") if interp else b""

    strtab = bytearray(b"\x00")
    needed_offs = []
    for lib in needed:
        needed_offs.append(len(strtab))
        strtab.extend(lib.encode("utf-8") + b"\x00")

    dyn_entries = bytearray()
    for off in needed_offs:
        dyn_entries.extend(struct.pack("<qQ", 1, off))  # DT_NEEDED
    if needed:
        dyn_entries.extend(struct.pack("<qQ", 5, 0x200))  # DT_STRTAB
        dyn_entries.extend(struct.pack("<qQ", 10, len(strtab)))  # DT_STRSZ
    dyn_entries.extend(struct.pack("<qQ", 0, 0))  # DT_NULL

    total_len = 0x300 + len(dyn_entries)
    buf = bytearray(total_len)

    phdrs.append(struct.pack("<IIQQQQQQ", 1, 5, 0, 0, 0, total_len, total_len, 0x1000))
    if interp_bytes:
        buf[0x100 : 0x100 + len(interp_bytes)] = interp_bytes
        phdrs.append(
            struct.pack("<IIQQQQQQ", 3, 4, 0x100, 0x100, 0x100, len(interp_bytes), len(interp_bytes), 1)
        )
    if needed:
        buf[0x200 : 0x200 + len(strtab)] = strtab
        buf[0x300 : 0x300 + len(dyn_entries)] = dyn_entries
        phdrs.append(
            struct.pack("<IIQQQQQQ", 2, 6, 0x300, 0x300, 0x300, len(dyn_entries), len(dyn_entries), 8)
        )

    e_ident = b"\x7fELF\x02\x01\x01" + b"\x00" * 9
    ehdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        e_ident, 3, 183, 1, 0, 64, 0, 0, 64, 56, len(phdrs), 0, 0, 0,
    )
    buf[0:64] = ehdr
    for idx, ph in enumerate(phdrs):
        buf[64 + idx * 56 : 64 + (idx + 1) * 56] = ph
    return bytes(buf)


def encode_varint(v: int) -> bytes:
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        if v:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def make_apex_manifest_pb(name: str, version: int) -> bytes:
    nb = name.encode("utf-8")
    return b"\x0a" + encode_varint(len(nb)) + nb + b"\x10" + encode_varint(version)


def raw_to_android_sparse(raw_path: Path, sparse_path: Path, blk_sz: int = 4096) -> None:
    data = raw_path.read_bytes()
    total_blks = len(data) // blk_sz
    chunks = []
    i = 0
    while i < total_blks:
        blk = data[i * blk_sz : (i + 1) * blk_sz]
        if blk == b"\x00" * blk_sz:
            j = i + 1
            while j < total_blks and data[j * blk_sz : (j + 1) * blk_sz] == b"\x00" * blk_sz:
                j += 1
            ctype = 0xCAC3 if (len(chunks) % 2 == 0) else 0xCAC2
            chunks.append((ctype, j - i, b"\x00\x00\x00\x00" if ctype == 0xCAC2 else b""))
            i = j
        else:
            j = i + 1
            while j < total_blks and data[j * blk_sz : (j + 1) * blk_sz] != b"\x00" * blk_sz:
                j += 1
            chunks.append((0xCAC1, j - i, data[i * blk_sz : j * blk_sz]))
            i = j

    hdr = struct.pack("<IHHHHIIII", 0xED26FF3A, 1, 0, 28, 12, blk_sz, total_blks, len(chunks), 0)
    with open(sparse_path, "wb") as f:
        f.write(hdr)
        for ctype, nblks, payload in chunks:
            f.write(struct.pack("<HHII", ctype, 0, nblks, 12 + len(payload)))
            if payload:
                f.write(payload)


def find_mkfs_ext4() -> str:
    for cand in ("mkfs.ext4", "/usr/sbin/mkfs.ext4", "/sbin/mkfs.ext4"):
        p = shutil.which(cand)
        if p:
            return p
    raise RuntimeError("mkfs.ext4 not found (install e2fsprogs)")


def main() -> int:
    mkfs = find_mkfs_ext4()
    with tempfile.TemporaryDirectory(prefix="phase1_ci_") as td:
        work = Path(td)

        # 1. Build synthetic com.android.runtime.apex
        apex_src = work / "apex_runtime_src"
        (apex_src / "bin").mkdir(parents=True)
        (apex_src / "lib64" / "bionic").mkdir(parents=True)
        (apex_src / "bin" / "linker64").write_bytes(make_minimal_aarch64_elf())
        os.chmod(apex_src / "bin" / "linker64", 0o755)
        (apex_src / "lib64" / "bionic" / "libc.so").write_bytes(make_minimal_aarch64_elf())
        (apex_src / "lib64" / "bionic" / "libdl.so").write_bytes(make_minimal_aarch64_elf())

        apex_payload_img = work / "apex_payload.img"
        with open(apex_payload_img, "wb") as f:
            f.truncate(2 * 1024 * 1024)
        subprocess.run([mkfs, "-q", "-d", str(apex_src), str(apex_payload_img)], check=True)

        apex_zip = work / "com.android.runtime.apex"
        with zipfile.ZipFile(apex_zip, "w", compression=zipfile.ZIP_STORED) as zf:
            zf.writestr("apex_manifest.pb", make_apex_manifest_pb("com.android.runtime", 310000000))
            zf.write(apex_payload_img, "apex_payload.img")

        # 2. Build synthetic AOSP 12 system.img & convert to sparse
        sys_src = work / "sys_src"
        (sys_src / "system" / "bin").mkdir(parents=True)
        (sys_src / "system" / "lib64").mkdir(parents=True)
        (sys_src / "system" / "apex").mkdir(parents=True)
        (sys_src / "system" / "bin" / "sh").write_bytes(
            make_minimal_aarch64_elf(interp="/system/bin/linker64", needed=["libc.so", "libdl.so"])
        )
        os.chmod(sys_src / "system" / "bin" / "sh", 0o755)
        shutil.copy2(apex_zip, sys_src / "system" / "apex" / "com.android.runtime.apex")
        os.symlink("/system/bin", sys_src / "bin")

        sys_raw = work / "system_raw.img"
        with open(sys_raw, "wb") as f:
            f.truncate(8 * 1024 * 1024)
        subprocess.run([mkfs, "-q", "-d", str(sys_src), str(sys_raw)], check=True)

        sys_sparse = work / "system_sparse.img"
        raw_to_android_sparse(sys_raw, sys_sparse)

        # 3. Execute tools/gsi_prepare.py
        out_rootfs = work / "rootfs"
        out_db = work / "rootfs_meta.db"
        subprocess.run(
            [sys.executable, str(GSI_PREPARE), str(sys_sparse), str(out_rootfs), "--meta-db", str(out_db)],
            check=True,
        )

        # 4. Verify filesystem layout
        assert (out_rootfs / "system" / "bin" / "sh").is_file()
        assert (out_rootfs / "apex" / "com.android.runtime" / "bin" / "linker64").is_file()
        assert (out_rootfs / "apex" / "com.android.runtime@310000000").is_symlink()
        assert (out_rootfs / "linkerconfig" / "ld.config.txt").is_file()

        # 5. Compile & run C++17 VfsMetaDb verification against include/vfs_meta_format.hpp
        cxx = shutil.which("g++") or shutil.which("clang++")
        if cxx:
            cpp_src = work / "test_vmdb.cpp"
            cpp_bin = REPO_ROOT / ".test_vmdb_bin"
            cpp_src.write_text(
                """
#include <cassert>
#include <iostream>
#include "vfs_meta_format.hpp"

int main(int argc, char** argv) {
    vguest::VfsMetaDb db;
    assert(db.open(argv[1]));
    assert(db.count() > 10);
    auto sh = db.find("/system/bin/sh");
    assert(sh.has_value() && (sh->entry->mode & 0111) != 0);
    auto linker = db.find("/apex/com.android.runtime/bin/linker64");
    assert(linker.has_value() && (linker->entry->flags & vguest::kVmdbFlagFromApex) != 0);
    assert(db.find("/apex/com.android.runtime@310000000").has_value());
    assert(!db.find("/does/not/exist").has_value());
    std::cout << "[PASS] C++17 VfsMetaDb mmap lookup verified (" << db.count() << " entries)\\n";
    return 0;
}
""",
                encoding="utf-8",
            )
            try:
                subprocess.run([cxx, "-std=c++17", f"-I{HEADER_DIR}", str(cpp_src), "-o", str(cpp_bin)], check=True)
                subprocess.run([str(cpp_bin), str(out_db)], check=True)
            finally:
                cpp_bin.unlink(missing_ok=True)

        print("[ALL PHASE 1 CI TESTS PASSED]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
