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
        // Sockets
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
    return probe_seccomp_user_notif() ? InterceptionTransport::kUserNotif
                                      : InterceptionTransport::kPtraceTrace;
}

std::vector<struct sock_filter> build_seccomp_filter(uint32_t trap_action) {
    const auto nrs = intercepted_syscalls();
    std::vector<struct sock_filter> prog;
    prog.reserve(nrs.size() + 14);

    // 1. Validate architecture == host arch; otherwise ALLOW
    prog.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                            static_cast<uint32_t>(offsetof(struct seccomp_data, arch))));
    prog.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, kHostAuditArch, 1, 0));
    prog.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));

    // 2. Load syscall number
    prog.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                            static_cast<uint32_t>(offsetof(struct seccomp_data, nr))));

    // 3. Fast in-kernel sub-filter for SYS_ioctl:
    //    Only trap Binder ('b' = 0x62) and Input evdev ('E' = 0x45) ioctl type bytes;
    //    all other ioctls (TTY, socket, pipe) pass natively at zero overhead.
    //    [+0] JEQ SYS_ioctl -> jt=0 (enter subfilter), jf=5 (skip subfilter)
    //    [+1] LD args[1] (low 32 bits of ioctl cmd on little-endian)
    //    [+2] ALU AND 0xFF00 (isolate _IOC_TYPE byte)
    //    [+3] JEQ ('b' << 8) -> jt=2 (RET trap_action), jf=0
    //    [+4] JEQ ('E' << 8) -> jt=1 (RET trap_action), jf=0
    //    [+5] RET SECCOMP_RET_ALLOW
    //    [+6] RET trap_action
    //    Wait: jf=6 skips all 6 instructions [+1..+6] to the main syscall table!
    prog.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_ioctl, 0, 6));
    prog.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                            static_cast<uint32_t>(offsetof(struct seccomp_data, args[1]))));
    prog.push_back(BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0x0000FF00U));
    prog.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, static_cast<uint32_t>('b') << 8, 2, 0));
    prog.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, static_cast<uint32_t>('E') << 8, 1, 0));
    prog.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    prog.push_back(BPF_STMT(BPF_RET | BPF_K, trap_action));

    // 4. Linear dispatch for remaining intercepted syscalls
    const size_t count = nrs.size();
    for (size_t i = 0; i < count; ++i) {
        uint8_t jt = static_cast<uint8_t>((count - 1 - i) + 1);
        prog.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, nrs[i], jt, 0));
    }

    prog.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
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
