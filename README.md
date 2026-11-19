# AOSP 12 ARM64 Unrooted Virtualization Layer (Phase 1)

Target host: Samsung Galaxy Tab S7+ (SM-T970/SM-T975, Snapdragon 865+, Android 13 One UI 5, Kernel 4.19.x).

## Repository Layout
- `tools/gsi_prepare.py` — Unprivileged raw/sparse ext4 extractor, `.apex`/`.capex` flattener, `/linkerconfig/ld.config.txt` generator, and ELF64 AArch64 verification gate.
- `include/vfs_meta_format.hpp` — C++17 zero-copy `mmap` reader for `rootfs_meta.db` (consumed by Phase 2 `guest_runner`).
- `tests/test_phase1.py` — Synthetic sparse-ext4 + `.apex` + C++17 `VfsMetaDb` CI test suite.
- `.github/workflows/phase1-gsi-prep.yml` — GitHub Actions CI tests and on-demand AOSP 12 GSI rootfs builder (`aosp12-arm64-rootfs.tar.zst`).

## Quickstart
1. Unzip into your repository root and push to GitHub.
2. Push automatically runs `unit-test` in GitHub Actions.
3. Open **Actions -> Phase 1 — AOSP 12 GSI Prep & Verification -> Run workflow**, paste a direct AOSP 12 ARM64 GSI URL, and download the generated `aosp12-arm64-rootfs.tar.zst` artifact (or publish it to a GitHub Release).
