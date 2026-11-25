#!/usr/bin/env python3
"""Prepare a Docker-exported Redroid ARM64 rootfs for VGuest.

1. Flattens any .apex / .capex archives in system/apex (and vendor/apex) into /apex/<pkg>
   if not already present as flattened directories.
2. Ensures required runtime mount/socket directories exist.
3. Builds a byte-exact VfsMetaDb v1 binary index (rootfs_meta.db) matching
   include/vfs_meta_format.hpp.
"""

import os
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

VMDB_MAGIC = b"VMDB"
VMDB_VERSION = 1
VMDB_ENTRY_SIZE = 48
FLAG_FROM_APEX = 1 << 2


def fnv1a_64(data: bytes) -> int:
    h = 0xCBF29CE484222325
    for b in data:
        h ^= b
        h = (h * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h


def guess_selinux_context(guest_path: str) -> str:
    if guest_path.startswith("/vendor"):
        return "u:object_r:vendor_file:s0"
    if guest_path.startswith("/data"):
        return "u:object_r:system_data_file:s0"
    if guest_path.startswith("/apex"):
        return "u:object_r:system_file:s0"
    if guest_path.startswith("/dev"):
        return "u:object_r:device:s0"
    return "u:object_r:system_file:s0"


def extract_ext4_with_debugfs(img_path: Path, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    # rdump recursively extracts files, dirs, and symlinks without requiring root mount
    subprocess.run(
        ["debugfs", "-R", f"rdump / {out_dir}", str(img_path)],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def flatten_apex_archive(apex_file: Path, apex_root: Path) -> str | None:
    """Extract a .apex (or .capex) into apex_root/<package_name>."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp_dir = Path(tmp)
        try:
            with zipfile.ZipFile(apex_file, "r") as zf:
                names = zf.namelist()
                if "original_apex" in names:
                    inner = tmp_dir / "original.apex"
                    inner.write_bytes(zf.read("original_apex"))
                    return flatten_apex_archive(inner, apex_root)
                if "apex_payload.img" not in names:
                    return None
                pkg_name = apex_file.stem
                if "apex_manifest.json" in names:
                    import json
                    manifest = json.loads(zf.read("apex_manifest.json").decode("utf-8", "ignore"))
                    pkg_name = manifest.get("name", pkg_name)
                elif "apex_manifest.pb" in names:
                    # Extract first printable com.android.* string from protobuf manifest
                    raw = zf.read("apex_manifest.pb")
                    import re
                    m = re.search(rb"com\.android\.[a-zA-Z0-9._-]+", raw)
                    if m:
                        pkg_name = m.group(0).decode("ascii")
                dest = apex_root / pkg_name
                if dest.exists() and any(dest.iterdir()):
                    return pkg_name
                payload_img = tmp_dir / "apex_payload.img"
                payload_img.write_bytes(zf.read("apex_payload.img"))
                extract_ext4_with_debugfs(payload_img, dest)
                # Copy manifest files for linkerconfig/ApexManager
                for mf in ("apex_manifest.pb", "apex_manifest.json"):
                    if mf in names:
                        (dest / mf).write_bytes(zf.read(mf))
                return pkg_name
        except Exception as exc:
            print(f"[warn] Skipping APEX {apex_file.name}: {exc}", file=sys.stderr)
            return None


def prepare_apexes(rootfs: Path) -> None:
    apex_root = rootfs / "apex"
    apex_root.mkdir(parents=True, exist_ok=True)
    flattened = 0
    for src_dir in (rootfs / "system/apex", rootfs / "system_ext/apex", rootfs / "vendor/apex"):
        if not src_dir.is_dir():
            continue
        for item in sorted(src_dir.iterdir()):
            if item.is_dir():
                dest = apex_root / item.name
                if not dest.exists():
                    shutil.copytree(item, dest, symlinks=True)
                    flattened += 1
            elif item.suffix in (".apex", ".capex"):
                pkg = flatten_apex_archive(item, apex_root)
                if pkg:
                    flattened += 1
    # Ensure com.android.art alias exists if only com.android.art.release / debug exists
    if not (apex_root / "com.android.art").exists():
        for cand in ("com.android.art.release", "com.android.art.debug", "com.android.art.testing"):
            if (apex_root / cand).exists():
                os.symlink(cand, apex_root / "com.android.art")
                break
    print(f"[redroid] APEX directories ready in /apex ({len(list(apex_root.iterdir()))} entries, +{flattened} flattened)")


def ensure_runtime_dirs(rootfs: Path) -> None:
    required = [
        "data/local/tmp",
        "data/system",
        "data/misc/odrefresh",
        "data/anr",
        "dev/__properties__",
        "dev/socket",
        "proc",
        "sys",
        "tmp",
        "linkerconfig",
        "vendor/lib64/egl",
        "vendor/lib64/hw",
        "vendor/bin/hw",
        "vendor/etc/vintf",
    ]
    for rel in required:
        (rootfs / rel).mkdir(parents=True, exist_ok=True)

    # Normalize permissions so unprivileged host APK can read/exec everything
    for dirpath, dirnames, filenames in os.walk(rootfs, followlinks=False):
        try:
            os.chmod(dirpath, 0o755)
        except OSError:
            pass
        for fn in filenames:
            fp = os.path.join(dirpath, fn)
            if os.path.islink(fp):
                continue
            try:
                st = os.lstat(fp)
                mode = 0o755 if (st.st_mode & 0o111) else 0o644
                os.chmod(fp, mode)
            except OSError:
                pass


def build_vfs_meta_db(rootfs: Path, db_out: Path) -> int:
    records = []
    for dirpath, dirnames, filenames in os.walk(rootfs, followlinks=False):
        rel_dir = os.path.relpath(dirpath, rootfs)
        guest_dir = "/" if rel_dir == "." else "/" + rel_dir.replace(os.sep, "/")
        if guest_dir != "/":
            st = os.lstat(dirpath)
            records.append((guest_dir, st.st_mode, FLAG_FROM_APEX if guest_dir.startswith("/apex/") else 0))
        for dn in dirnames:
            dp = os.path.join(dirpath, dn)
            if os.path.islink(dp):
                rel_dp = os.path.relpath(dp, rootfs)
                gp = "/" + rel_dp.replace(os.sep, "/")
                try:
                    st = os.lstat(dp)
                    records.append((gp, st.st_mode, FLAG_FROM_APEX if gp.startswith("/apex/") else 0))
                except OSError:
                    pass
        for name in filenames:
            fp = os.path.join(dirpath, name)
            rel_fp = os.path.relpath(fp, rootfs)
            guest_path = "/" + rel_fp.replace(os.sep, "/")
            try:
                st = os.lstat(fp)
            except OSError:
                continue
            flags = FLAG_FROM_APEX if guest_path.startswith("/apex/") else 0
            records.append((guest_path, st.st_mode, flags))

    # Build string table (deduplicated selinux labels, raw guest paths)
    str_buf = bytearray()
    selinux_cache: dict[str, int] = {}

    def add_str(s: str, dedup: bool = False) -> tuple[int, int]:
        if dedup and s in selinux_cache:
            return selinux_cache[s], len(s.encode("utf-8"))
        b = s.encode("utf-8")
        off = len(str_buf)
        str_buf.extend(b)
        str_buf.append(0)
        if dedup:
            selinux_cache[s] = off
        return off, len(b)

    entries = []
    for guest_path, mode, flags in records:
        p_bytes = guest_path.encode("utf-8")
        h = fnv1a_64(p_bytes)
        p_off, p_len = add_str(guest_path, dedup=False)
        se = guess_selinux_context(guest_path)
        s_off, s_len = add_str(se, dedup=True)
        uid = 0
        gid = 2000 if (guest_path.startswith("/system/bin") or guest_path.startswith("/vendor/bin")) else 0
        entries.append((h, guest_path, p_off, p_len, s_len, s_off, uid, gid, mode, 0, 0, 0, flags))

    entries.sort(key=lambda e: (e[0], e[1]))

    entry_count = len(entries)
    entry_table_off = 64
    string_table_off = entry_table_off + entry_count * VMDB_ENTRY_SIZE
    total_size = string_table_off + len(str_buf)

    header = struct.pack(
        "<4sIIIIQQQ20s",
        VMDB_MAGIC,
        VMDB_VERSION,
        VMDB_ENTRY_SIZE,
        0,
        entry_count,
        entry_table_off,
        string_table_off,
        total_size,
        b"\x00" * 20,
    )
    assert len(header) == 64

    with open(db_out, "wb") as f:
        f.write(header)
        for e in entries:
            rec = struct.pack(
                "<QIHHI7I",
                e[0],  # path_hash
                e[2],  # path_off
                e[3],  # path_len
                e[4],  # selinux_len
                e[5],  # selinux_off
                e[6],  # uid
                e[7],  # gid
                e[8],  # mode
                e[9],  # rdev
                e[10], # caps_lo
                e[11], # caps_hi
                e[12], # flags
            )
            assert len(rec) == VMDB_ENTRY_SIZE
            f.write(rec)
        f.write(str_buf)

    print(f"[redroid] Built VfsMetaDb: {entry_count} entries, {total_size} bytes -> {db_out}")
    return entry_count


def main() -> int:
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <rootfs_dir> <rootfs_meta.db>", file=sys.stderr)
        return 2
    rootfs = Path(sys.argv[1]).resolve()
    db_out = Path(sys.argv[2]).resolve()
    if not (rootfs / "system/bin/sh").exists():
        print(f"[error] {rootfs}/system/bin/sh not found!", file=sys.stderr)
        return 1
    prepare_apexes(rootfs)
    ensure_runtime_dirs(rootfs)
    build_vfs_meta_db(rootfs, db_out)
    for check in ("system/bin/sh", "system/bin/app_process64", "system/bin/servicemanager", "system/bin/surfaceflinger"):
        exists = (rootfs / check).exists()
        print(f"[check] /{check}: {'OK' if exists else 'MISSING'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
