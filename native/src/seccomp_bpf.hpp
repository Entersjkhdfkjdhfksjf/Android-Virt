#pragma once

#include <cstdint>
#include <linux/filter.h>
#include <vector>

namespace vguest {

enum class InterceptionTransport {
    kAuto,
    kUserNotif,  // SECCOMP_RET_USER_NOTIF (Linux 5.0+)
    kPtraceTrace // SECCOMP_RET_TRACE + ptrace (Samsung Tab S7+ Kernel 4.19.x compatible)
};

// Probes kernel support for SECCOMP_RET_USER_NOTIF via seccomp(SECCOMP_GET_ACTION_AVAIL).
bool probe_seccomp_user_notif() noexcept;

// Resolves kAuto into kUserNotif (5.0+) or kPtraceTrace (4.19.x).
InterceptionTransport select_transport(InterceptionTransport requested) noexcept;

// Compiles a cBPF filter that returns SECCOMP_RET_ALLOW for ~95% of syscalls
// and returns `trap_action` (SECCOMP_RET_TRACE or SECCOMP_RET_USER_NOTIF)
// only for intercepted path, credential, mount, and IPC syscalls.
std::vector<struct sock_filter> build_seccomp_filter(uint32_t trap_action);

// Installs the compiled cBPF filter into the current process.
// For SECCOMP_RET_USER_NOTIF, returns the listener FD (>= 0).
// For SECCOMP_RET_TRACE, returns 0 on success, -1 on failure.
int install_seccomp_filter(const std::vector<struct sock_filter>& prog,
                           bool request_listener_fd);

}  // namespace vguest
