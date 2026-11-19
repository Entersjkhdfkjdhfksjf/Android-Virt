#pragma once

#include <string>
#include <string_view>
#include <sys/types.h>

namespace vguest {

enum class PathKind {
    kNormalRootfs,   // Translated to <rootfs_root>/<guest_path>
    kHostPassThru,   // Pass through to host kernel (/dev/null, /dev/urandom, etc.)
    kVirtualProc,    // Synthetic memfd (/proc/mounts, /proc/self/attr/current, etc.)
    kVirtualSys,     // Synthetic memfd (/sys/fs/selinux/enforce, etc.)
    kVirtualBinder,  // Phase 4 hook (/dev/binder, /dev/hwbinder, /dev/vndbinder)
    kVirtualInput,   // Phase 5 hook (/dev/input/event*)
};

struct TranslatedPath {
    PathKind kind = PathKind::kNormalRootfs;
    std::string guest_path;  // Canonical guest-absolute path (e.g., "/system/bin/sh")
    std::string host_path;   // Host filesystem path (e.g., "/data/.../rootfs/system/bin/sh")
};

class PathTranslator {
public:
    explicit PathTranslator(std::string rootfs_root);

    const std::string& rootfs_root() const noexcept { return rootfs_root_; }

    // Canonicalizes a POSIX path (resolves ".", "..", duplicate slashes) without touching disk.
    static std::string normalize_posix(std::string_view path);

    // Converts a host path back into a guest-absolute path by stripping rootfs_root_.
    std::string host_to_guest(std::string_view host_path) const;

    // Translates a guest path (relative to dirfd or guest cwd) into a host path + classification.
    // If follow_final_symlink is true, resolves guest-rooted symlinks inside rootfs without escaping.
    TranslatedPath translate(pid_t pid, int dirfd, std::string_view raw_path,
                             bool follow_final_symlink = true) const;

    // Resolves a guest-absolute path directly (used in unit tests and execve ELF inspection).
    TranslatedPath translate_absolute(std::string_view guest_abs,
                                      bool follow_final_symlink = true) const;

    // Translates an AF_UNIX socket path; prefixes abstract sockets with a container namespace.
    std::string translate_unix_socket(std::string_view raw_sun_path, bool is_abstract) const;

private:
    std::string resolve_dirfd_guest(pid_t pid, int dirfd) const;
    std::string resolve_symlinks_in_rootfs(std::string_view guest_abs,
                                           bool follow_final_symlink) const;
    PathKind classify_guest_path(std::string_view guest_abs) const;

    std::string rootfs_root_;
};

}  // namespace vguest
