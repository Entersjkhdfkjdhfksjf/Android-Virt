#include "seccomp_bpf.hpp"

#include <cerrno>
#include <cstddef>
#include <linux/audit.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef SECCOMP_GET_ACTION_AVAIL
#define SECCOMP_GET_ACTION_AVAIL 2
#endif

#ifndef SECCOMP_RET_USER_NOTIF
#define SECCOMP_RET_USER_NOTIF 0x7fc00000U
#endif

#ifndef SECCOMP_FILTER_FLAG_NEW_LISTENER
#define SECCOMP_FILTER_FLAG_NEW_LISTENER (1UL << 3)
#endif

#ifndef SYS_seccomp
#if defined(__aarch64__)
#define SYS_seccomp 277
#elif defined(__x86_64__)
#define SYS_seccomp 317
#endif
#endif

namespace vguest {

namespace {

#if defined(__aarch64__)
constexpr uint32_t kHostAuditArch = AUDIT_ARCH_AARCH64;
#elif defined(__x86_64__)
constexpr uint32_t kHostAuditArch = AUDIT_ARCH_X86_64;
#else
#error "Unsupported architecture: expected aarch64 or x86_64"
#endif

std::vector<uint32_t> intercepted_syscalls() {
    std::vector<uint32_t> nrs = {
        // Path & filesystem operations
        SYS_openat,
        SYS_newfstatat,
        SYS_faccessat,
        SYS_readlinkat,
        SYS_unlinkat,
        SYS_mkdirat,
        SYS_symlinkat,
        SYS_linkat,
        SYS_truncate,
        SYS_chdir,
        SYS_getcwd,
        SYS_utimensat,
        SYS_execve,
        SYS_execveat,
        // Credentials & metadata
        SYS_getuid,
        SYS_geteuid,
        SYS_getgid,
        SYS_getegid,
        SYS_getresuid,
        SYS_getresgid,
        SYS_getgroups,
        SYS_setuid,
        SYS_setgid,
        SYS_setresuid,
        SYS_setresgid,
        SYS_setreuid,
        SYS_setregid,
        SYS_setgroups,
        SYS_fchownat,
        SYS_fchown,
        SYS_fchmodat,
        SYS_fchmod,
        SYS_capget,
        SYS_capset,
        // Mounts & namespaces
        SYS_mount,
        SYS_umount2,
        SYS_chroot,
        SYS_pivot_root,
        SYS_unshare,
        SYS_sethostname,
        SYS_setdomainname,
        // Sockets & prctl
        SYS_bind,
        SYS_connect,
    };
#ifdef SYS_openat2
    nrs.push_back(SYS_openat2);
#endif
#ifdef SYS_statx
    nrs.push_back(SYS_statx);
#endif
#ifdef SYS_faccessat2
    nrs.push_back(SYS_faccessat2);
#endif
#ifdef SYS_renameat
    nrs.push_back(SYS_renameat);
#endif
#ifdef SYS_renameat2
    nrs.push_back(SYS_renameat2);
#endif
#ifdef SYS_open
    nrs.push_back(SYS_open);
#endif
#ifdef SYS_stat
    nrs.push_back(SYS_stat);
#endif
#ifdef SYS_lstat
    nrs.push_back(SYS_lstat);
#endif
#ifdef SYS_access
    nrs.push_back(SYS_access);
#endif
#ifdef SYS_readlink
    nrs.push_back(SYS_readlink);
#endif
    return nrs;
}

}  // namespace

bool probe_seccomp_user_notif() noexcept {
    uint32_t action = SECCOMP_RET_USER_NOTIF;
    long rc = ::syscall(SYS_seccomp, SECCOMP_GET_ACTION_AVAIL, 0, &action);
    return rc == 0;
}

InterceptionTransport select_transport(InterceptionTransport requested) noexcept {
    if (requested == InterceptionTransport::kPtraceTrace) {
        return InterceptionTransport::kPtraceTrace;
    }
    if (requested == InterceptionTransport::kUserNotif) {
        return probe_seccomp_user_notif() ? InterceptionTransport::kUserNotif
                                          : InterceptionTransport::kPtraceTrace;
    }
    // kAuto: Prefer ptrace-backed SECCOMP_RET_TRACE on 4.19.x (where user_notif is absent)
    // and also use SECCOMP_RET_TRACE when full memory-rewrite path translation is needed.
    return probe_seccomp_user_notif() ? InterceptionTransport::kUserNotif
                                      : InterceptionTransport::kPtraceTrace;
}

std::vector<struct sock_filter> build_seccomp_filter(uint32_t trap_action) {
    const auto nrs = intercepted_syscalls();
    std::vector<struct sock_filter> prog;
    prog.reserve(nrs.size() + 6);

    // 1. Validate architecture == host arch; otherwise ALLOW (let kernel handle)
    prog.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                            static_cast<uint32_t>(offsetof(struct seccomp_data, arch))));
    // Jump over syscall checks to ALLOW if arch mismatch
    // We emit ALLOW at index (prog.size() + nrs.size() + 2)
    prog.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, kHostAuditArch, 1, 0));
    prog.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));

    // 2. Load syscall number
    prog.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                            static_cast<uint32_t>(offsetof(struct seccomp_data, nr))));

    // 3. Emit linear dispatch to TRAP label (placed right after ALLOW)
    // Total instructions after this loop:
    //   [end + 0]: RET SECCOMP_RET_ALLOW
    //   [end + 1]: RET trap_action
    const size_t count = nrs.size();
    for (size_t i = 0; i < count; ++i) {
        uint8_t jt = static_cast<uint8_t>((count - 1 - i) + 1);  // Jump to RET trap_action
        prog.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, nrs[i], jt, 0));
    }

    // Default fast-path: native execution
    prog.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    // Intercepted path
    prog.push_back(BPF_STMT(BPF_RET | BPF_K, trap_action));
    return prog;
}

int install_seccomp_filter(const std::vector<struct sock_filter>& prog,
                           bool request_listener_fd) {
    if (::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        return -1;
    }
    struct sock_fprog fprog {};
    fprog.len = static_cast<unsigned short>(prog.size());
    fprog.filter = const_cast<struct sock_filter*>(prog.data());

    unsigned int flags = request_listener_fd ? SECCOMP_FILTER_FLAG_NEW_LISTENER : 0U;
    long rc = ::syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, flags, &fprog);
    return static_cast<int>(rc);
}

}  // namespace vguest
