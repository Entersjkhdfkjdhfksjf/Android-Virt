#pragma once

#include <string>
#include <string_view>
#include <sys/types.h>

#include "cred_table.hpp"

namespace vguest {

// Generates synthetic /proc and /sys content into anonymous memfd buffers
// so AOSP 12 daemons see a clean, permissive Android 12 Linux environment.
class PseudoFs {
public:
    explicit PseudoFs(std::string rootfs_root);

    // Returns synthetic file contents for a virtual /proc or /sys path,
    // or empty string if unhandled.
    std::string generate_content(pid_t pid, std::string_view guest_path,
                                 const VirtualCreds& creds) const;

    // Creates a sealed-offset memfd populated with the synthetic content (caller owns FD).
    int open_virtual_memfd(pid_t pid, std::string_view guest_path,
                           const VirtualCreds& creds) const;

private:
    std::string build_proc_mounts() const;
    std::string build_proc_mountinfo() const;
    std::string build_proc_status(pid_t pid, const VirtualCreds& creds) const;
    std::string build_proc_maps(pid_t pid) const;

    std::string rootfs_root_;
};

}  // namespace vguest
