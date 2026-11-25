#include "supervisor.hpp"

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <chrono>
#include <cstring>
#include <elf.h>
#include <fcntl.h>
#include <fstream>
#include <linux/seccomp.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <linux/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(__aarch64__)
#include <asm/ptrace.h>
#ifndef NT_PRSTATUS
#define NT_PRSTATUS 1
#endif
#ifndef NT_ARM_SYSTEM_CALL
#define NT_ARM_SYSTEM_CALL 0x404
#endif
#endif

#ifndef SECCOMP_RET_USER_NOTIF
#define SECCOMP_RET_USER_NOTIF 0x7fc00000U
#endif
#ifndef SECCOMP_USER_NOTIF_FLAG_CONTINUE
#define SECCOMP_USER_NOTIF_FLAG_CONTINUE (1UL << 0)
#endif
#ifndef SECCOMP_IOCTL_NOTIF_RECV
struct seccomp_notif {
    uint64_t id;
    uint32_t pid;
    uint32_t flags;
    struct seccomp_data data;
};
struct seccomp_notif_resp {
    uint64_t id;
    int64_t val;
    int32_t error;
    uint32_t flags;
};
#define SECCOMP_IOWR(nr, type) _IOWR('!', nr, type)
#define SECCOMP_IOW(nr, type) _IOW('!', nr, type)
#define SECCOMP_IOCTL_NOTIF_RECV SECCOMP_IOWR(0, struct seccomp_notif)
#define SECCOMP_IOCTL_NOTIF_SEND SECCOMP_IOWR(1, struct seccomp_notif_resp)
#define SECCOMP_IOCTL_NOTIF_ID_VALID SECCOMP_IOW(2, uint64_t)
#endif

#ifndef PR_SET_CHILD_SUBREAPER
#define PR_SET_CHILD_SUBREAPER 36
#endif

namespace vguest {

namespace {

struct ArchRegs {
#if defined(__aarch64__)
    struct user_pt_regs r {};
    int64_t orig_sysno = 0;

    bool load(pid_t pid) {
        struct iovec iov { &r, sizeof(r) };
        if (::ptrace(PTRACE_GETREGSET, pid, reinterpret_cast<void*>(NT_PRSTATUS), &iov) != 0) {
            return false;
        }
        orig_sysno = static_cast<int64_t>(r.regs[8]);
        return true;
    }
    bool store(pid_t pid) {
        struct iovec iov { &r, sizeof(r) };
        return ::ptrace(PTRACE_SETREGSET, pid, reinterpret_cast<void*>(NT_PRSTATUS), &iov) == 0;
    }
    bool cancel_syscall(pid_t pid) {
        int nr = -1;
        struct iovec iov { &nr, sizeof(nr) };
        return ::ptrace(PTRACE_SETREGSET, pid, reinterpret_cast<void*>(NT_ARM_SYSTEM_CALL), &iov) == 0;
    }
    int64_t sysno() const { return orig_sysno; }
    uint64_t arg(int idx) const { return r.regs[idx]; }
    void set_arg(int idx, uint64_t v) { r.regs[idx] = v; }
    int64_t ret() const { return static_cast<int64_t>(r.regs[0]); }
    void set_ret(int64_t v) { r.regs[0] = static_cast<uint64_t>(v); }
    uint64_t sp() const { return r.sp; }
#elif defined(__x86_64__)
    struct user_regs_struct r {};

    bool load(pid_t pid) {
        return ::ptrace(PTRACE_GETREGS, pid, nullptr, &r) == 0;
    }
    bool store(pid_t pid) {
        return ::ptrace(PTRACE_SETREGS, pid, nullptr, &r) == 0;
    }
    bool cancel_syscall(pid_t pid) {
        r.orig_rax = static_cast<unsigned long long>(-1);
        return store(pid);
    }
    int64_t sysno() const { return static_cast<int64_t>(r.orig_rax); }
    uint64_t arg(int idx) const {
        switch (idx) {
            case 0: return r.rdi;
            case 1: return r.rsi;
            case 2: return r.rdx;
            case 3: return r.r10;
            case 4: return r.r8;
            case 5: return r.r9;
            default: return 0;
        }
    }
    void set_arg(int idx, uint64_t v) {
        switch (idx) {
            case 0: r.rdi = v; break;
            case 1: r.rsi = v; break;
            case 2: r.rdx = v; break;
            case 3: r.r10 = v; break;
            case 4: r.r8 = v; break;
            case 5: r.r9 = v; break;
            default: break;
        }
    }
    int64_t ret() const { return static_cast<int64_t>(r.rax); }
    void set_ret(int64_t v) { r.rax = static_cast<uint64_t>(v); }
    uint64_t sp() const { return r.rsp; }
#endif
};

uint64_t scratch_addr_below_sp(uint64_t sp, size_t len) {
    uint64_t aligned = (len + 15ULL) & ~15ULL;
    return (sp - 256ULL - aligned) & ~15ULL;
}

}  // namespace

Supervisor::Supervisor(SupervisorConfig cfg)
    : cfg_(std::move(cfg)),
      translator_(cfg_.rootfs_root),
      pseudo_fs_(cfg_.rootfs_root),
      prop_service_(cfg_.rootfs_root),
      vbinder_(cfg_.rootfs_root,
               GuestMemOps{
                   [this](pid_t p, uint64_t a, void* o, size_t l) { return read_guest_mem(p, a, o, l); },
                   [this](pid_t p, uint64_t a, const void* d, size_t l) { return write_guest_mem(p, a, d, l); },
                   [](pid_t p, const std::string& sub) { return find_guest_mmap_base(p, sub); },
                   [this](pid_t stgid, int sfd, pid_t ttid) { return dup_fd_into_target(stgid, sfd, ttid); },
                   [this](pid_t stgid, pid_t stid, int sfd) { return grab_fd_from_sender(stgid, stid, sfd); },
                   [this](int hfd, pid_t ttid) { return dup_held_fd_into_target(hfd, ttid); },
                   [](int hfd) { if (hfd >= 0) ::close(hfd); },
               }),
      vinput_(cfg_.rootfs_root, 1400, 876,
              InputMemOps{[this](pid_t p, uint64_t a, const void* d, size_t l) {
                  return write_guest_mem(p, a, d, l);
              }}),
      logd_(cfg_.rootfs_root) {}

uint64_t Supervisor::find_guest_mmap_base(pid_t pid, const std::string& path_substr) {
    char maps_path[64];
    std::snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", static_cast<int>(pid));
    std::ifstream in(maps_path);
    if (!in.is_open()) return 0;
    std::string line;
    while (std::getline(in, line)) {
        if (line.find(path_substr) != std::string::npos) {
            size_t dash = line.find('-');
            if (dash != std::string::npos) {
                return std::strtoull(line.substr(0, dash).c_str(), nullptr, 16);
            }
        }
    }
    return 0;
}

bool Supervisor::init_fd_relay() {
    close_fd_relay();
    ::mkdir((cfg_.rootfs_root + "/tmp").c_str(), 0777);
    fd_relay_path_ = cfg_.rootfs_root + "/tmp/.vfd";
    ::unlink(fd_relay_path_.c_str());
    int s = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (s < 0) return false;
    struct sockaddr_un addr {};
    addr.sun_family = AF_UNIX;
    if (fd_relay_path_.size() >= sizeof(addr.sun_path)) {
        ::close(s);
        return false;
    }
    std::strncpy(addr.sun_path, fd_relay_path_.c_str(), sizeof(addr.sun_path) - 1);
    if (::bind(s, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) != 0 ||
        ::listen(s, 16) != 0) {
        ::close(s);
        return false;
    }
    ::chmod(fd_relay_path_.c_str(), 0666);
    fd_relay_listen_fd_ = s;
    return true;
}

void Supervisor::close_fd_relay() {
    if (fd_relay_listen_fd_ >= 0) {
        ::close(fd_relay_listen_fd_);
        fd_relay_listen_fd_ = -1;
    }
    if (!fd_relay_path_.empty()) {
        ::unlink(fd_relay_path_.c_str());
    }
}

int64_t Supervisor::inject_syscall(pid_t tid, long sysno, uint64_t a0, uint64_t a1, uint64_t a2,
                                   uint64_t a3, uint64_t a4, uint64_t a5) const {
    ArchRegs saved;
    if (!saved.load(tid)) return -ESRCH;

    bool rewind_pc = (injected_stop_tids_.count(tid) > 0);
    ArchRegs inj = saved;
#if defined(__aarch64__)
    if (rewind_pc) inj.r.pc -= 4;
#elif defined(__x86_64__)
    if (rewind_pc) inj.r.rip -= 2;
#endif
    inj.set_arg(0, a0);
    inj.set_arg(1, a1);
    inj.set_arg(2, a2);
    inj.set_arg(3, a3);
    inj.set_arg(4, a4);
    inj.set_arg(5, a5);
#if defined(__aarch64__)
    inj.r.regs[8] = static_cast<uint64_t>(sysno);
    inj.store(tid);
    int nr = static_cast<int>(sysno);
    struct iovec iov { &nr, sizeof(nr) };
    ::ptrace(PTRACE_SETREGSET, tid, reinterpret_cast<void*>(NT_ARM_SYSTEM_CALL), &iov);
#elif defined(__x86_64__)
    inj.r.orig_rax = static_cast<uint64_t>(sysno);
    inj.r.rax = static_cast<uint64_t>(sysno);
    inj.store(tid);
#endif

    ::ptrace(PTRACE_SYSCALL, tid, nullptr, nullptr);
    int st = 0;
    int64_t retval = -EIO;
    bool expecting_entry = rewind_pc;
    while (::waitpid(tid, &st, __WALL) > 0) {
        if (!WIFSTOPPED(st)) break;
        int s = WSTOPSIG(st);
        if (s == (SIGTRAP | 0x80)) {
            if (expecting_entry) {
                expecting_entry = false;
                ::ptrace(PTRACE_SYSCALL, tid, nullptr, nullptr);
                continue;
            }
            ArchRegs out;
            if (out.load(tid)) retval = out.ret();
            break;
        }
        ::ptrace(PTRACE_SYSCALL, tid, nullptr, nullptr);
    }

    injected_stop_tids_.insert(tid);
    saved.store(tid);
    return retval;
}

int Supervisor::scm_grab_fd(pid_t sender_tid, int sender_fd) const {
    if (fd_relay_listen_fd_ < 0 || sender_tid <= 0 || sender_fd < 0) return -1;
    ArchRegs saved;
    if (!saved.load(sender_tid)) return -1;

    int64_t gs = inject_syscall(sender_tid, SYS_socket, AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, 0, 0, 0);
    if (gs < 0) return -1;

    struct RelayBlob {
        struct sockaddr_un addr;
        struct msghdr msg;
        struct iovec iov;
        char dummy;
        char pad[7];
        union {
            char buf[CMSG_SPACE(sizeof(int))];
            struct cmsghdr align;
        } cmsg_u;
    };
    uint64_t scratch = scratch_addr_below_sp(saved.sp(), sizeof(RelayBlob));
    RelayBlob blob {};
    blob.addr.sun_family = AF_UNIX;
    std::strncpy(blob.addr.sun_path, fd_relay_path_.c_str(), sizeof(blob.addr.sun_path) - 1);
    blob.dummy = 'F';
    blob.iov.iov_base = reinterpret_cast<void*>(scratch + offsetof(RelayBlob, dummy));
    blob.iov.iov_len = 1;
    blob.msg.msg_iov = reinterpret_cast<struct iovec*>(scratch + offsetof(RelayBlob, iov));
    blob.msg.msg_iovlen = 1;
    blob.msg.msg_control = reinterpret_cast<void*>(scratch + offsetof(RelayBlob, cmsg_u));
    blob.msg.msg_controllen = sizeof(blob.cmsg_u.buf);
    auto* cm = reinterpret_cast<struct cmsghdr*>(blob.cmsg_u.buf);
    cm->cmsg_len = CMSG_LEN(sizeof(int));
    cm->cmsg_level = SOL_SOCKET;
    cm->cmsg_type = SCM_RIGHTS;
    std::memcpy(CMSG_DATA(cm), &sender_fd, sizeof(int));

    int held = -1;
    if (write_guest_mem(sender_tid, scratch, &blob, sizeof(blob))) {
        int64_t crc = inject_syscall(sender_tid, SYS_connect, static_cast<uint64_t>(gs),
                                     scratch + offsetof(RelayBlob, addr), sizeof(blob.addr), 0, 0, 0);
        if (crc == 0) {
            int conn = ::accept4(fd_relay_listen_fd_, nullptr, nullptr, SOCK_CLOEXEC);
            if (conn >= 0) {
                int64_t src = inject_syscall(sender_tid, SYS_sendmsg, static_cast<uint64_t>(gs),
                                             scratch + offsetof(RelayBlob, msg), 0, 0, 0, 0);
                if (src > 0) {
                    char rch = 0;
                    struct iovec riov { &rch, 1 };
                    union {
                        char buf[CMSG_SPACE(sizeof(int))];
                        struct cmsghdr align;
                    } rcmsg_u {};
                    struct msghdr rmsg {};
                    rmsg.msg_iov = &riov;
                    rmsg.msg_iovlen = 1;
                    rmsg.msg_control = rcmsg_u.buf;
                    rmsg.msg_controllen = sizeof(rcmsg_u.buf);
                    if (::recvmsg(conn, &rmsg, MSG_CMSG_CLOEXEC) > 0) {
                        struct cmsghdr* rcm = CMSG_FIRSTHDR(&rmsg);
                        if (rcm && rcm->cmsg_level == SOL_SOCKET && rcm->cmsg_type == SCM_RIGHTS) {
                            std::memcpy(&held, CMSG_DATA(rcm), sizeof(int));
                        }
                    }
                }
                ::close(conn);
            }
        }
    }
    (void)inject_syscall(sender_tid, SYS_close, static_cast<uint64_t>(gs), 0, 0, 0, 0, 0);
    return held;
}

int Supervisor::scm_send_fd(pid_t target_tid, int held_fd) const {
    if (fd_relay_listen_fd_ < 0 || target_tid <= 0 || held_fd < 0) return -1;
    ArchRegs saved;
    if (!saved.load(target_tid)) return -1;

    int64_t gs = inject_syscall(target_tid, SYS_socket, AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, 0, 0, 0);
    if (gs < 0) return -1;

    struct RelayBlob {
        struct sockaddr_un addr;
        struct msghdr msg;
        struct iovec iov;
        char dummy;
        char pad[7];
        union {
            char buf[CMSG_SPACE(sizeof(int))];
            struct cmsghdr align;
        } cmsg_u;
    };
    uint64_t scratch = scratch_addr_below_sp(saved.sp(), sizeof(RelayBlob));
    RelayBlob blob {};
    blob.addr.sun_family = AF_UNIX;
    std::strncpy(blob.addr.sun_path, fd_relay_path_.c_str(), sizeof(blob.addr.sun_path) - 1);
    blob.iov.iov_base = reinterpret_cast<void*>(scratch + offsetof(RelayBlob, dummy));
    blob.iov.iov_len = 1;
    blob.msg.msg_iov = reinterpret_cast<struct iovec*>(scratch + offsetof(RelayBlob, iov));
    blob.msg.msg_iovlen = 1;
    blob.msg.msg_control = reinterpret_cast<void*>(scratch + offsetof(RelayBlob, cmsg_u));
    blob.msg.msg_controllen = sizeof(blob.cmsg_u.buf);

    int new_fd = -1;
    if (write_guest_mem(target_tid, scratch, &blob, sizeof(blob))) {
        int64_t crc = inject_syscall(target_tid, SYS_connect, static_cast<uint64_t>(gs),
                                     scratch + offsetof(RelayBlob, addr), sizeof(blob.addr), 0, 0, 0);
        if (crc == 0) {
            int conn = ::accept4(fd_relay_listen_fd_, nullptr, nullptr, SOCK_CLOEXEC);
            if (conn >= 0) {
                char sch = 'R';
                struct iovec siov { &sch, 1 };
                union {
                    char buf[CMSG_SPACE(sizeof(int))];
                    struct cmsghdr align;
                } scmsg_u {};
                struct msghdr smsg {};
                smsg.msg_iov = &siov;
                smsg.msg_iovlen = 1;
                smsg.msg_control = scmsg_u.buf;
                smsg.msg_controllen = sizeof(scmsg_u.buf);
                struct cmsghdr* scm = CMSG_FIRSTHDR(&smsg);
                scm->cmsg_len = CMSG_LEN(sizeof(int));
                scm->cmsg_level = SOL_SOCKET;
                scm->cmsg_type = SCM_RIGHTS;
                std::memcpy(CMSG_DATA(scm), &held_fd, sizeof(int));
                if (::sendmsg(conn, &smsg, 0) > 0) {
                    int64_t rrc = inject_syscall(target_tid, SYS_recvmsg, static_cast<uint64_t>(gs),
                                                 scratch + offsetof(RelayBlob, msg), MSG_CMSG_CLOEXEC, 0, 0, 0);
                    if (rrc > 0) {
                        RelayBlob out_blob {};
                        if (read_guest_mem(target_tid, scratch, &out_blob, sizeof(out_blob))) {
                            auto* rcm = reinterpret_cast<struct cmsghdr*>(out_blob.cmsg_u.buf);
                            if (rcm->cmsg_level == SOL_SOCKET && rcm->cmsg_type == SCM_RIGHTS) {
                                std::memcpy(&new_fd, CMSG_DATA(rcm), sizeof(int));
                            }
                        }
                    }
                }
                ::close(conn);
            }
        }
    }
    (void)inject_syscall(target_tid, SYS_close, static_cast<uint64_t>(gs), 0, 0, 0, 0, 0);
    return new_fd;
}

int Supervisor::grab_fd_from_sender(pid_t sender_tgid, pid_t sender_tid, int sender_fd) const {
    if (sender_tgid <= 0 || sender_fd < 0) return -1;
    // Always prefer SCM_RIGHTS so the exact kernel struct file* is duplicated
    // (critical for /dev/ashmem FMQ buffers, AF_UNIX BitTube/InputChannel sockets, and memfds).
    int fd = scm_grab_fd(sender_tid, sender_fd);
    if (fd >= 0) return fd;
    std::string proc_path = "/proc/" + std::to_string(static_cast<int>(sender_tgid)) +
                            "/fd/" + std::to_string(sender_fd);
    fd = ::open(proc_path.c_str(), O_RDWR | O_CLOEXEC);
    if (fd < 0 && (errno == EACCES || errno == EROFS)) {
        fd = ::open(proc_path.c_str(), O_RDONLY | O_CLOEXEC);
    }
    return fd;
}

int Supervisor::dup_held_fd_into_target(int held_fd, pid_t target_tid) const {
    if (held_fd < 0 || target_tid <= 0) return -1;
    int new_fd = scm_send_fd(target_tid, held_fd);
    if (new_fd >= 0) return new_fd;
    ArchRegs saved;
    if (!saved.load(target_tid)) return -1;

    std::string proc_path = "/proc/" + std::to_string(static_cast<int>(::getpid())) +
                            "/fd/" + std::to_string(held_fd);
    proc_path.push_back('\0');
    uint64_t scratch = scratch_addr_below_sp(saved.sp(), proc_path.size());
    if (write_guest_mem(target_tid, scratch, proc_path.data(), proc_path.size())) {
        int64_t nfd = inject_syscall(target_tid, SYS_openat, static_cast<uint64_t>(AT_FDCWD),
                                     scratch, static_cast<uint64_t>(O_RDWR | O_CLOEXEC), 0, 0, 0);
        if (nfd == -EACCES || nfd == -EROFS) {
            nfd = inject_syscall(target_tid, SYS_openat, static_cast<uint64_t>(AT_FDCWD),
                                 scratch, static_cast<uint64_t>(O_RDONLY | O_CLOEXEC), 0, 0, 0);
        }
        if (nfd >= 0) return static_cast<int>(nfd);
    }
    return -1;
}

int Supervisor::dup_fd_into_target(pid_t sender_tgid, int sender_fd, pid_t target_tid) const {
    if (sender_tgid <= 0 || sender_fd < 0 || target_tid <= 0) return -1;
    ArchRegs saved;
    if (!saved.load(target_tid)) return -1;

    std::string proc_path = "/proc/" + std::to_string(static_cast<int>(sender_tgid)) +
                            "/fd/" + std::to_string(sender_fd);
    proc_path.push_back('\0');
    uint64_t scratch = scratch_addr_below_sp(saved.sp(), proc_path.size());
    if (!write_guest_mem(target_tid, scratch, proc_path.data(), proc_path.size())) {
        return -1;
    }

    auto run_openat = [&](int flags, bool rewind_pc) -> int {
        ArchRegs inj = saved;
#if defined(__aarch64__)
        if (rewind_pc) inj.r.pc -= 4;
#elif defined(__x86_64__)
        if (rewind_pc) inj.r.rip -= 2;
#endif
        inj.set_arg(0, static_cast<uint64_t>(AT_FDCWD));
        inj.set_arg(1, scratch);
        inj.set_arg(2, static_cast<uint64_t>(flags));
        inj.set_arg(3, 0);
        inj.store(target_tid);
#if defined(__aarch64__)
        int nr = SYS_openat;
        struct iovec iov { &nr, sizeof(nr) };
        ::ptrace(PTRACE_SETREGSET, target_tid, reinterpret_cast<void*>(NT_ARM_SYSTEM_CALL), &iov);
#elif defined(__x86_64__)
        inj.r.orig_rax = SYS_openat;
        inj.store(target_tid);
#endif
        ::ptrace(PTRACE_SYSCALL, target_tid, nullptr, nullptr);
        int st = 0;
        while (::waitpid(target_tid, &st, __WALL) > 0) {
            if (!WIFSTOPPED(st)) return -1;
            int s = WSTOPSIG(st);
            if (s == (SIGTRAP | 0x80)) {
                ArchRegs out;
                if (!out.load(target_tid)) return -1;
                if (rewind_pc) {
                    // Rewound call stops at syscall entry first, then syscall exit
                    rewind_pc = false;
                    ::ptrace(PTRACE_SYSCALL, target_tid, nullptr, nullptr);
                    continue;
                }
                return static_cast<int>(out.ret());
            }
            ::ptrace(PTRACE_SYSCALL, target_tid, nullptr, nullptr);
        }
        return -1;
    };

    int new_fd = run_openat(O_RDWR | O_CLOEXEC, false);
    if (new_fd == -EACCES || new_fd == -EROFS) {
        new_fd = run_openat(O_RDONLY | O_CLOEXEC, true);
    }

    saved.store(target_tid);
    return (new_fd >= 0) ? new_fd : -1;
}

bool Supervisor::read_guest_mem(pid_t pid, uint64_t addr, void* out, size_t len) const {
    if (len == 0) return true;
    struct iovec local { out, len };
    struct iovec remote { reinterpret_cast<void*>(addr), len };
    ssize_t n = ::process_vm_readv(pid, &local, 1, &remote, 1, 0);
    if (n == static_cast<ssize_t>(len)) return true;

    auto* dst = reinterpret_cast<uint8_t*>(out);
    size_t off = 0;
    while (off < len) {
        errno = 0;
        long word = ::ptrace(PTRACE_PEEKDATA, pid, reinterpret_cast<void*>(addr + off), nullptr);
        if (word == -1 && errno != 0) return false;
        size_t take = std::min(sizeof(long), len - off);
        std::memcpy(dst + off, &word, take);
        off += take;
    }
    return true;
}

bool Supervisor::write_guest_mem(pid_t pid, uint64_t addr, const void* data, size_t len) const {
    if (len == 0) return true;
    struct iovec local { const_cast<void*>(data), len };
    struct iovec remote { reinterpret_cast<void*>(addr), len };
    ssize_t n = ::process_vm_writev(pid, &local, 1, &remote, 1, 0);
    if (n == static_cast<ssize_t>(len)) return true;

    const auto* src = reinterpret_cast<const uint8_t*>(data);
    size_t off = 0;
    while (off < len) {
        long word = 0;
        size_t take = std::min(sizeof(long), len - off);
        if (take < sizeof(long)) {
            errno = 0;
            word = ::ptrace(PTRACE_PEEKDATA, pid, reinterpret_cast<void*>(addr + off), nullptr);
            if (word == -1 && errno != 0) return false;
        }
        std::memcpy(&word, src + off, take);
        if (::ptrace(PTRACE_POKEDATA, pid, reinterpret_cast<void*>(addr + off),
                     reinterpret_cast<void*>(word)) != 0) {
            return false;
        }
        off += take;
    }
    return true;
}

bool Supervisor::read_guest_cstring(pid_t pid, uint64_t addr, std::string& out,
                                    size_t max_len) const {
    out.clear();
    if (addr == 0) return false;
    char chunk[256];
    while (out.size() < max_len) {
        size_t want = std::min(sizeof(chunk), max_len - out.size());
        uint64_t cur = addr + out.size();
        size_t to_page_end = 4096U - static_cast<size_t>(cur & 4095ULL);
        want = std::min(want, to_page_end);
        if (!read_guest_mem(pid, cur, chunk, want)) return !out.empty();
        for (size_t i = 0; i < want; ++i) {
            if (chunk[i] == '\0') return true;
            out.push_back(chunk[i]);
        }
    }
    return true;
}

std::string Supervisor::read_elf_interp(const std::string& host_binary_path) {
    std::ifstream f(host_binary_path, std::ios::binary);
    if (!f.is_open()) return "";
    Elf64_Ehdr ehdr {};
    f.read(reinterpret_cast<char*>(&ehdr), sizeof(ehdr));
    if (!f || std::memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0 ||
        ehdr.e_ident[EI_CLASS] != ELFCLASS64) {
        return "";
    }
    f.seekg(static_cast<std::streamoff>(ehdr.e_phoff), std::ios::beg);
    for (uint16_t i = 0; i < ehdr.e_phnum; ++i) {
        Elf64_Phdr phdr {};
        f.read(reinterpret_cast<char*>(&phdr), sizeof(phdr));
        if (!f) break;
        if (phdr.p_type == PT_INTERP && phdr.p_filesz > 0 && phdr.p_filesz < 512) {
            std::string interp(static_cast<size_t>(phdr.p_filesz), '\0');
            f.seekg(static_cast<std::streamoff>(phdr.p_offset), std::ios::beg);
            f.read(interp.data(), static_cast<std::streamsize>(phdr.p_filesz));
            while (!interp.empty() && interp.back() == '\0') interp.pop_back();
            return interp;
        }
    }
    return "";
}

int Supervisor::run(const std::vector<std::string>& guest_argv,
                    const std::vector<std::string>& guest_env) {
    if (guest_argv.empty()) return 1;

    ::prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);

    (void)logd_.start();
    (void)init_fd_relay();
    (void)vinput_.start();

    if (cfg_.enable_property_service) {
        if (!prop_service_.start()) {
            std::fprintf(stderr, "[guest_runner] warning: failed to start PropertyService\n");
        } else if (cfg_.verbose) {
            std::fprintf(stderr, "[guest_runner] PropertyService listening on %s\n",
                         prop_service_.socket_path().c_str());
        }
    }

    if (!cfg_.meta_db_path.empty()) {
        if (!meta_db_.open(cfg_.meta_db_path.c_str())) {
            std::fprintf(stderr, "[guest_runner] warning: failed to open %s\n",
                         cfg_.meta_db_path.c_str());
        } else if (cfg_.verbose) {
            std::fprintf(stderr, "[guest_runner] loaded VfsMetaDb (%u entries)\n",
                         meta_db_.count());
        }
    }

    InterceptionTransport active = select_transport(cfg_.transport);
    if (cfg_.transport == InterceptionTransport::kAuto) {
        active = InterceptionTransport::kPtraceTrace;
    }

    if (cfg_.verbose) {
        std::fprintf(stderr, "[guest_runner] transport=%s rootfs=%s vbinder=3-domain build=p7r-capbset-rxlimit\n",
                     active == InterceptionTransport::kUserNotif ? "SECCOMP_RET_USER_NOTIF"
                                                                 : "SECCOMP_RET_TRACE+ptrace",
                     cfg_.rootfs_root.c_str());
    }

    TranslatedPath entry_bin = translator_.translate_absolute(guest_argv[0], true);
    std::string interp_guest = read_elf_interp(entry_bin.host_path);

    std::vector<std::string> exec_args;
    std::string host_exec_target = entry_bin.host_path;
    if (!interp_guest.empty()) {
        TranslatedPath interp_tp = translator_.translate_absolute(interp_guest, true);
        if (::access(interp_tp.host_path.c_str(), X_OK) == 0) {
            host_exec_target = interp_tp.host_path;
            exec_args.push_back(interp_tp.host_path);
            exec_args.push_back(entry_bin.host_path);
            for (size_t i = 1; i < guest_argv.size(); ++i) {
                exec_args.push_back(guest_argv[i]);
            }
        }
    }
    if (exec_args.empty()) {
        exec_args.push_back(entry_bin.host_path);
        for (size_t i = 1; i < guest_argv.size(); ++i) {
            exec_args.push_back(guest_argv[i]);
        }
    }

    int sockpair[2] = {-1, -1};
    if (active == InterceptionTransport::kUserNotif) {
        if (::socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockpair) != 0) {
            prop_service_.stop();
            return 1;
        }
    }

    pid_t child = ::fork();
    if (child < 0) {
        prop_service_.stop();
        return 1;
    }

    if (child == 0) {
        ::prctl(PR_SET_PDEATHSIG, SIGKILL);
        if (::chdir(cfg_.rootfs_root.c_str()) != 0) _exit(126);

        if (active == InterceptionTransport::kPtraceTrace) {
            if (::ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) != 0) _exit(126);
            ::raise(SIGSTOP);
            auto prog = build_seccomp_filter(SECCOMP_RET_TRACE);
            if (install_seccomp_filter(prog, false) != 0) _exit(126);
        } else {
            ::close(sockpair[0]);
            auto prog = build_seccomp_filter(SECCOMP_RET_USER_NOTIF);
            int lfd = install_seccomp_filter(prog, true);
            if (lfd < 0) _exit(126);
            char dummy = 'L';
            struct iovec iov { &dummy, 1 };
            union {
                char buf[CMSG_SPACE(sizeof(int))];
                struct cmsghdr align;
            } cmsg_u {};
            struct msghdr msg {};
            msg.msg_iov = &iov;
            msg.msg_iovlen = 1;
            msg.msg_control = cmsg_u.buf;
            msg.msg_controllen = sizeof(cmsg_u.buf);
            struct cmsghdr* cm = CMSG_FIRSTHDR(&msg);
            cm->cmsg_level = SOL_SOCKET;
            cm->cmsg_type = SCM_RIGHTS;
            cm->cmsg_len = CMSG_LEN(sizeof(int));
            std::memcpy(CMSG_DATA(cm), &lfd, sizeof(int));
            ::sendmsg(sockpair[1], &msg, 0);
            ::close(lfd);
            ::close(sockpair[1]);
        }

        std::vector<char*> c_argv;
        c_argv.reserve(exec_args.size() + 1);
        for (auto& s : exec_args) c_argv.push_back(s.data());
        c_argv.push_back(nullptr);

        std::vector<char*> c_env;
        for (auto& e : const_cast<std::vector<std::string>&>(guest_env)) {
            c_env.push_back(e.data());
        }
        c_env.push_back(nullptr);

        ::execve(host_exec_target.c_str(), c_argv.data(),
                 guest_env.empty() ? environ : c_env.data());
        std::fprintf(stderr, "[guest_runner] execve(%s) failed: errno=%d (%s)\n",
                     host_exec_target.c_str(), errno, std::strerror(errno));
        _exit(127);
    }

    int rc = 0;
    if (active == InterceptionTransport::kUserNotif) {
        ::close(sockpair[1]);
        char dummy = 0;
        struct iovec iov { &dummy, 1 };
        union {
            char buf[CMSG_SPACE(sizeof(int))];
            struct cmsghdr align;
        } cmsg_u {};
        struct msghdr msg {};
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_u.buf;
        msg.msg_controllen = sizeof(cmsg_u.buf);
        int listener_fd = -1;
        if (::recvmsg(sockpair[0], &msg, 0) > 0) {
            struct cmsghdr* cm = CMSG_FIRSTHDR(&msg);
            if (cm && cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SCM_RIGHTS) {
                std::memcpy(&listener_fd, CMSG_DATA(cm), sizeof(int));
            }
        }
        ::close(sockpair[0]);
        rc = run_user_notif_loop(child, listener_fd);
    } else {
        rc = run_ptrace_loop(child);
    }

    vinput_.stop();
    close_fd_relay();
    logd_.stop();
    prop_service_.stop();
    return rc;
}

void Supervisor::wake_parked_binder_threads(const std::vector<WakeEvent>& wakes) {
    for (const auto& w : wakes) {
        ArchRegs wregs;
        if (wregs.load(w.pid)) {
            wregs.cancel_syscall(w.pid);
            wregs.set_ret(w.return_value);
            wregs.store(w.pid);
        }
        auto& wproc = registry_.get_or_create(w.pid, cfg_.initial_creds);
        wproc.parked_in_binder = false;
        injected_stop_tids_.erase(w.pid);
        ::ptrace(PTRACE_CONT, w.pid, nullptr, nullptr);
    }
}

int Supervisor::run_ptrace_loop(pid_t root_child) {
    int status = 0;
    if (::waitpid(root_child, &status, 0) < 0) return 1;

    unsigned long opts = PTRACE_O_TRACESECCOMP | PTRACE_O_TRACECLONE |
                         PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK |
                         PTRACE_O_TRACEEXEC | PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD;
    if (::ptrace(PTRACE_SETOPTIONS, root_child, nullptr, reinterpret_cast<void*>(opts)) != 0) {
        return 1;
    }

    registry_.get_or_create(root_child, cfg_.initial_creds);
    ::ptrace(PTRACE_CONT, root_child, nullptr, nullptr);

    int root_exit_code = 0;
    auto last_diag_dump = std::chrono::steady_clock::now();

    while (!registry_.empty()) {
        if (cfg_.verbose) {
            auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::seconds>(now - last_diag_dump).count() >= 15) {
                last_diag_dump = now;
                vbinder_.dump_state(stderr);
            }
        }
        pid_t pid = ::waitpid(-1, &status, __WALL);
        if (pid < 0) {
            if (errno == EINTR) continue;
            break;
        }

        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            if (WIFSIGNALED(status) && cfg_.verbose) {
                std::fprintf(stderr, "[guest_runner] child pid=%d died with signal %d\n",
                             static_cast<int>(pid), WTERMSIG(status));
            }
            if (pid == root_child) {
                root_exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : (128 + WTERMSIG(status));
            }
            pid_t exiting_tgid = registry_.get_or_create(pid, cfg_.initial_creds).tgid;
            registry_.erase(pid);
            if (!registry_.has_tgid(exiting_tgid)) {
                vinput_.on_process_exit(exiting_tgid);
                auto wakes = vbinder_.on_process_exit(exiting_tgid);
                wake_parked_binder_threads(wakes);
            }
            continue;
        }
        if (!WIFSTOPPED(status)) continue;

        const int sig = WSTOPSIG(status);
        const int event = (status >> 16) & 0xFFFF;
        ProcessState& proc = registry_.get_or_create(pid, cfg_.initial_creds);

        if (sig == SIGTRAP && event == PTRACE_EVENT_SECCOMP) {
            handle_ptrace_seccomp_entry(pid, proc);
            if (proc.parked_in_binder) {
                // Intentionally parked until a peer sends BR_TRANSACTION/BR_REPLY
                continue;
            }
            injected_stop_tids_.erase(pid);
            if (proc.expecting_syscall_exit) {
                ::ptrace(PTRACE_SYSCALL, pid, nullptr, nullptr);
            } else {
                ::ptrace(PTRACE_CONT, pid, nullptr, nullptr);
            }
        } else if (sig == (SIGTRAP | 0x80) && proc.expecting_syscall_exit) {
            proc.expecting_syscall_exit = false;
            handle_ptrace_syscall_exit(pid, proc);
            ::ptrace(PTRACE_CONT, pid, nullptr, nullptr);
        } else if (sig == SIGTRAP &&
                   (event == PTRACE_EVENT_FORK || event == PTRACE_EVENT_VFORK ||
                    event == PTRACE_EVENT_CLONE)) {
            unsigned long new_pid = 0;
            if (::ptrace(PTRACE_GETEVENTMSG, pid, nullptr, &new_pid) == 0 && new_pid > 0) {
                registry_.inherit_from_parent(pid, static_cast<pid_t>(new_pid),
                                              event == PTRACE_EVENT_CLONE);
            }
            ::ptrace(PTRACE_CONT, pid, nullptr, nullptr);
        } else if (sig == SIGTRAP && event == PTRACE_EVENT_EXEC) {
            proc.expecting_syscall_exit = false;
            proc.parked_in_binder = false;
            proc.exit_op = PendingExitOp{};
            ::ptrace(PTRACE_CONT, pid, nullptr, nullptr);
        } else if (sig == SIGSYS) {
            ArchRegs sregs;
            if (sregs.load(pid)) {
                int64_t snr = sregs.sysno();
                if (snr == SYS_setuid) {
                    uint32_t v = static_cast<uint32_t>(sregs.arg(0));
                    proc.creds.uid = proc.creds.euid = proc.creds.suid = v;
                } else if (snr == SYS_setgid) {
                    uint32_t v = static_cast<uint32_t>(sregs.arg(0));
                    proc.creds.gid = proc.creds.egid = proc.creds.sgid = v;
                } else if (snr == SYS_setreuid) {
                    uint32_t r = static_cast<uint32_t>(sregs.arg(0));
                    uint32_t e = static_cast<uint32_t>(sregs.arg(1));
                    if (r != static_cast<uint32_t>(-1)) proc.creds.uid = r;
                    if (e != static_cast<uint32_t>(-1)) proc.creds.euid = e;
                } else if (snr == SYS_setregid) {
                    uint32_t r = static_cast<uint32_t>(sregs.arg(0));
                    uint32_t e = static_cast<uint32_t>(sregs.arg(1));
                    if (r != static_cast<uint32_t>(-1)) proc.creds.gid = r;
                    if (e != static_cast<uint32_t>(-1)) proc.creds.egid = e;
                } else if (snr == SYS_setresuid) {
                    uint32_t r = static_cast<uint32_t>(sregs.arg(0));
                    uint32_t e = static_cast<uint32_t>(sregs.arg(1));
                    uint32_t s = static_cast<uint32_t>(sregs.arg(2));
                    if (r != static_cast<uint32_t>(-1)) proc.creds.uid = r;
                    if (e != static_cast<uint32_t>(-1)) proc.creds.euid = e;
                    if (s != static_cast<uint32_t>(-1)) proc.creds.suid = s;
                } else if (snr == SYS_setresgid) {
                    uint32_t r = static_cast<uint32_t>(sregs.arg(0));
                    uint32_t e = static_cast<uint32_t>(sregs.arg(1));
                    uint32_t s = static_cast<uint32_t>(sregs.arg(2));
                    if (r != static_cast<uint32_t>(-1)) proc.creds.gid = r;
                    if (e != static_cast<uint32_t>(-1)) proc.creds.egid = e;
                    if (s != static_cast<uint32_t>(-1)) proc.creds.sgid = s;
                }
                if (cfg_.verbose) {
                    std::fprintf(stderr, "[guest_runner] spoofed host-blocked syscall %lld -> 0\n",
                                 static_cast<long long>(snr));
                }
                sregs.set_ret(0);
                sregs.store(pid);
            }
            ::ptrace(PTRACE_CONT, pid, nullptr, nullptr);
        } else {
            int deliver_sig = (sig == SIGTRAP || sig == SIGSTOP) ? 0 : sig;
            ::ptrace(PTRACE_CONT, pid, nullptr,
                     reinterpret_cast<void*>(static_cast<uintptr_t>(deliver_sig)));
        }
    }

    return root_exit_code;
}

void Supervisor::handle_ptrace_seccomp_entry(pid_t pid, ProcessState& proc) {
    ArchRegs regs;
    if (!regs.load(pid)) return;
    const int64_t nr = regs.sysno();

    auto skip_with_ret = [&](int64_t retval) {
        regs.cancel_syscall(pid);
        regs.set_ret(retval);
        regs.store(pid);
    };

    // --- 0. Phase 4 Virtual Binder ioctl & epoll interception ---
    if (nr == SYS_ioctl) {
        int fd = static_cast<int>(regs.arg(0));
        unsigned long cmd = static_cast<unsigned long>(regs.arg(1));
        uint64_t arg_ptr = regs.arg(2);
        if (vinput_.is_virtual_input_fd(proc.tgid, fd)) {
            int64_t iret = vinput_.handle_ioctl(proc.tgid, fd, cmd, arg_ptr);
            skip_with_ret(iret);
            return;
        }
        if (vbinder_.is_virtual_binder_fd(proc.tgid, fd)) {
            BinderIoctlResult bres = vbinder_.handle_ioctl(proc.tgid, pid, fd, cmd, arg_ptr, proc.creds.euid);
            if (bres.became_context_mgr && bres.domain == BinderDomain::kBinder) {
                prop_service_.set("servicemanager.ready", "true");
                if (cfg_.verbose) {
                    std::fprintf(stderr, "[guest_runner] servicemanager registered as /dev/binder handle 0\n");
                }
            }
            wake_parked_binder_threads(bres.wakes);
            if (bres.park_caller) {
                proc.parked_in_binder = true;
                return;
            }
            skip_with_ret(bres.return_value);
        }
        return;
    }
    if (nr == SYS_epoll_ctl) {
        int epfd = static_cast<int>(regs.arg(0));
        int op = static_cast<int>(regs.arg(1));
        int target_fd = static_cast<int>(regs.arg(2));
        uint64_t ev_ptr = regs.arg(3);
        if (vbinder_.handle_epoll_ctl(proc.tgid, epfd, op, target_fd, ev_ptr)) {
            skip_with_ret(0);
            return;
        }
        return;
    }
    if (nr == SYS_epoll_pwait) {
        int epfd = static_cast<int>(regs.arg(0));
        if (vbinder_.is_watched_epfd(proc.tgid, epfd)) {
            BinderIoctlResult eres = vbinder_.handle_epoll_pwait(
                proc.tgid, pid, epfd, regs.arg(1), static_cast<int>(regs.arg(2)));
            if (eres.park_caller) {
                proc.parked_in_binder = true;
                return;
            }
            skip_with_ret(eres.return_value);
            return;
        }
        return;
    }

    // --- 1. Virtual Credential Getters ---
    if (nr == SYS_getuid)  { skip_with_ret(proc.creds.uid); return; }
    if (nr == SYS_geteuid) { skip_with_ret(proc.creds.euid); return; }
    if (nr == SYS_getgid)  { skip_with_ret(proc.creds.gid); return; }
    if (nr == SYS_getegid) { skip_with_ret(proc.creds.egid); return; }
    if (nr == SYS_getresuid) {
        write_guest_mem(pid, regs.arg(0), &proc.creds.uid, sizeof(uint32_t));
        write_guest_mem(pid, regs.arg(1), &proc.creds.euid, sizeof(uint32_t));
        write_guest_mem(pid, regs.arg(2), &proc.creds.suid, sizeof(uint32_t));
        skip_with_ret(0);
        return;
    }
    if (nr == SYS_getresgid) {
        write_guest_mem(pid, regs.arg(0), &proc.creds.gid, sizeof(uint32_t));
        write_guest_mem(pid, regs.arg(1), &proc.creds.egid, sizeof(uint32_t));
        write_guest_mem(pid, regs.arg(2), &proc.creds.sgid, sizeof(uint32_t));
        skip_with_ret(0);
        return;
    }

    // --- 2. Virtual Credential Setters & Mount / Cap / Ownership Spoofing ---
    if (nr == SYS_setuid) {
        uint32_t v = static_cast<uint32_t>(regs.arg(0));
        proc.creds.uid = proc.creds.euid = proc.creds.suid = v;
        skip_with_ret(0);
        return;
    }
    if (nr == SYS_setgid) {
        uint32_t v = static_cast<uint32_t>(regs.arg(0));
        proc.creds.gid = proc.creds.egid = proc.creds.sgid = v;
        skip_with_ret(0);
        return;
    }
    if (nr == SYS_setreuid) {
        uint32_t r = static_cast<uint32_t>(regs.arg(0));
        uint32_t e = static_cast<uint32_t>(regs.arg(1));
        if (r != static_cast<uint32_t>(-1)) proc.creds.uid = r;
        if (e != static_cast<uint32_t>(-1)) proc.creds.euid = e;
        skip_with_ret(0);
        return;
    }
    if (nr == SYS_setregid) {
        uint32_t r = static_cast<uint32_t>(regs.arg(0));
        uint32_t e = static_cast<uint32_t>(regs.arg(1));
        if (r != static_cast<uint32_t>(-1)) proc.creds.gid = r;
        if (e != static_cast<uint32_t>(-1)) proc.creds.egid = e;
        skip_with_ret(0);
        return;
    }
    if (nr == SYS_setresuid) {
        uint32_t r = static_cast<uint32_t>(regs.arg(0));
        uint32_t e = static_cast<uint32_t>(regs.arg(1));
        uint32_t s = static_cast<uint32_t>(regs.arg(2));
        if (r != static_cast<uint32_t>(-1)) proc.creds.uid = r;
        if (e != static_cast<uint32_t>(-1)) proc.creds.euid = e;
        if (s != static_cast<uint32_t>(-1)) proc.creds.suid = s;
        skip_with_ret(0);
        return;
    }
    if (nr == SYS_setresgid) {
        uint32_t r = static_cast<uint32_t>(regs.arg(0));
        uint32_t e = static_cast<uint32_t>(regs.arg(1));
        uint32_t s = static_cast<uint32_t>(regs.arg(2));
        if (r != static_cast<uint32_t>(-1)) proc.creds.gid = r;
        if (e != static_cast<uint32_t>(-1)) proc.creds.egid = e;
        if (s != static_cast<uint32_t>(-1)) proc.creds.sgid = s;
        skip_with_ret(0);
        return;
    }
    if (nr == SYS_prctl) {
        int opt = static_cast<int>(regs.arg(0));
        // Spoof capability bounding-set / ambient / keepcaps / seccomp prctls inside Zygote SpecializeCommon()
        if (opt == 23 /*PR_CAPBSET_READ*/) {
            skip_with_ret((regs.arg(1) <= 40) ? 1 : -EINVAL);
            return;
        }
        if (opt == 24 /*PR_CAPBSET_DROP*/ || opt == 8 /*PR_SET_KEEPCAPS*/ ||
            opt == 47 /*PR_CAP_AMBIENT*/ || opt == 22 /*PR_SET_SECCOMP*/) {
            skip_with_ret(0);
            return;
        }
        return;
    }
#ifdef SYS_seccomp
    if (nr == SYS_seccomp) {
        // Prevent guest Zygote/system_server from stacking conflicting seccomp filters over guest_runner
        skip_with_ret(0);
        return;
    }
#endif
    if (nr == SYS_prlimit64) {
        // Allow getrlimit (old_limit != 0) natively; spoof setrlimit-only calls (new_limit != 0 && old_limit == 0)
        // so Zygote SetRLimits() never aborts with EPERM on unprivileged host.
        if (regs.arg(2) != 0 && regs.arg(3) == 0) {
            skip_with_ret(0);
            return;
        }
        return;
    }
    if (nr == SYS_fchownat) {
        int dirfd = static_cast<int>(regs.arg(0));
        uid_t owner = static_cast<uid_t>(regs.arg(2));
        gid_t group = static_cast<gid_t>(regs.arg(3));
        int flags = static_cast<int>(regs.arg(4));
        std::string raw_path;
        std::string gpath;
        if (read_guest_cstring(pid, regs.arg(1), raw_path)) {
            if (raw_path.empty() && (flags & AT_EMPTY_PATH) != 0) {
                char proc_fd[128];
                std::snprintf(proc_fd, sizeof(proc_fd), "/proc/%d/fd/%d", static_cast<int>(pid), dirfd);
                char link_buf[4096];
                ssize_t n = ::readlink(proc_fd, link_buf, sizeof(link_buf) - 1);
                if (n > 0) {
                    link_buf[n] = '\0';
                    gpath = translator_.host_to_guest(std::string_view(link_buf, static_cast<size_t>(n)));
                }
            } else {
                bool follow = (flags & AT_SYMLINK_NOFOLLOW) == 0;
                TranslatedPath tp = translator_.translate(pid, dirfd, raw_path, follow);
                gpath = tp.guest_path;
            }
        }
        if (!gpath.empty()) {
            auto& rm = runtime_meta_[gpath];
            if (owner != static_cast<uid_t>(-1)) {
                rm.uid = owner;
                rm.has_uid = true;
            }
            if (group != static_cast<gid_t>(-1)) {
                rm.gid = group;
                rm.has_gid = true;
            }
        }
        skip_with_ret(0);
        return;
    }
    if (nr == SYS_fchown) {
        int fd = static_cast<int>(regs.arg(0));
        uid_t owner = static_cast<uid_t>(regs.arg(1));
        gid_t group = static_cast<gid_t>(regs.arg(2));
        char proc_fd[128];
        std::snprintf(proc_fd, sizeof(proc_fd), "/proc/%d/fd/%d", static_cast<int>(pid), fd);
        char link_buf[4096];
        ssize_t n = ::readlink(proc_fd, link_buf, sizeof(link_buf) - 1);
        if (n > 0) {
            link_buf[n] = '\0';
            std::string gpath = translator_.host_to_guest(std::string_view(link_buf, static_cast<size_t>(n)));
            if (!gpath.empty()) {
                auto& rm = runtime_meta_[gpath];
                if (owner != static_cast<uid_t>(-1)) {
                    rm.uid = owner;
                    rm.has_uid = true;
                }
                if (group != static_cast<gid_t>(-1)) {
                    rm.gid = group;
                    rm.has_gid = true;
                }
            }
        }
        skip_with_ret(0);
        return;
    }
    if (nr == SYS_setxattr || nr == SYS_lsetxattr || nr == SYS_fsetxattr ||
        nr == SYS_removexattr || nr == SYS_lremovexattr || nr == SYS_fremovexattr) {
        skip_with_ret(0);
        return;
    }
    if (nr == SYS_getxattr || nr == SYS_lgetxattr || nr == SYS_fgetxattr) {
        skip_with_ret(-ENODATA);
        return;
    }
    if (nr == SYS_capget || nr == SYS_capset) {
        struct CapHeader { uint32_t version; int32_t pid; };
        struct CapData { uint32_t effective; uint32_t permitted; uint32_t inheritable; };
        constexpr uint32_t kCapVer1 = 0x19980330U;
        constexpr uint32_t kCapVer2 = 0x20071026U;
        constexpr uint32_t kCapVer3 = 0x20080522U;

        uint64_t hdr_ptr = regs.arg(0);
        uint64_t data_ptr = regs.arg(1);
        CapHeader hdr {};
        if (hdr_ptr == 0 || !read_guest_mem(pid, hdr_ptr, &hdr, sizeof(hdr))) {
            skip_with_ret(-EFAULT);
            return;
        }
        bool known_ver = (hdr.version == kCapVer1 || hdr.version == kCapVer2 || hdr.version == kCapVer3);
        if (!known_ver) {
            hdr.version = kCapVer3;
            write_guest_mem(pid, hdr_ptr, &hdr, sizeof(hdr));
            skip_with_ret(data_ptr == 0 ? 0 : -EINVAL);
            return;
        }
        size_t n_words = (hdr.version == kCapVer1) ? 1 : 2;
        if (nr == SYS_capget) {
            if (data_ptr != 0) {
                const VirtualCreds& c = proc.creds;
                CapData d[2] {};
                d[0].effective = static_cast<uint32_t>(c.cap_effective & 0xFFFFFFFFULL);
                d[0].permitted = static_cast<uint32_t>(c.cap_permitted & 0xFFFFFFFFULL);
                d[0].inheritable = static_cast<uint32_t>(c.cap_inheritable & 0xFFFFFFFFULL);
                d[1].effective = static_cast<uint32_t>(c.cap_effective >> 32);
                d[1].permitted = static_cast<uint32_t>(c.cap_permitted >> 32);
                d[1].inheritable = static_cast<uint32_t>(c.cap_inheritable >> 32);
                write_guest_mem(pid, data_ptr, d, sizeof(CapData) * n_words);
            }
            skip_with_ret(0);
            return;
        } else {
            if (data_ptr != 0) {
                CapData d[2] {};
                if (read_guest_mem(pid, data_ptr, d, sizeof(CapData) * n_words)) {
                    if (n_words == 1) {
                        proc.creds.cap_effective = d[0].effective;
                        proc.creds.cap_permitted = d[0].permitted;
                        proc.creds.cap_inheritable = d[0].inheritable;
                    } else {
                        proc.creds.cap_effective = (static_cast<uint64_t>(d[1].effective) << 32) | d[0].effective;
                        proc.creds.cap_permitted = (static_cast<uint64_t>(d[1].permitted) << 32) | d[0].permitted;
                        proc.creds.cap_inheritable = (static_cast<uint64_t>(d[1].inheritable) << 32) | d[0].inheritable;
                    }
                }
            }
            skip_with_ret(0);
            return;
        }
    }
    if (nr == SYS_setgroups ||
        nr == SYS_mount || nr == SYS_umount2 || nr == SYS_chroot || nr == SYS_pivot_root ||
        nr == SYS_sethostname || nr == SYS_setdomainname || nr == SYS_unshare) {
        skip_with_ret(0);
        return;
    }

    // --- 3. AF_UNIX connect/bind redirection ---
    if (nr == SYS_connect || nr == SYS_bind) {
        uint64_t addr_ptr = regs.arg(1);
        uint64_t addr_len = regs.arg(2);
        if (addr_ptr != 0 && addr_len > offsetof(struct sockaddr_un, sun_path) &&
            addr_len <= sizeof(struct sockaddr_un)) {
            struct sockaddr_un sa {};
            if (read_guest_mem(pid, addr_ptr, &sa, static_cast<size_t>(addr_len)) &&
                sa.sun_family == AF_UNIX) {
                size_t path_bytes = static_cast<size_t>(addr_len) - offsetof(struct sockaddr_un, sun_path);
                bool is_abstract = (path_bytes > 0 && sa.sun_path[0] == '\0');
                struct sockaddr_un out_sa {};
                out_sa.sun_family = AF_UNIX;
                uint64_t new_len = 0;

                if (is_abstract && path_bytes > 1) {
                    std::string_view raw_abs(sa.sun_path + 1, path_bytes - 1);
                    std::string ns_abs = translator_.translate_unix_socket(raw_abs, true);
                    size_t copy_len = std::min(ns_abs.size(), sizeof(out_sa.sun_path) - 1);
                    out_sa.sun_path[0] = '\0';
                    std::memcpy(out_sa.sun_path + 1, ns_abs.data(), copy_len);
                    new_len = offsetof(struct sockaddr_un, sun_path) + 1 + copy_len;
                } else if (!is_abstract) {
                    size_t slen = ::strnlen(sa.sun_path, path_bytes);
                    std::string host_sock = translator_.translate_unix_socket(
                        std::string_view(sa.sun_path, slen), false);
                    if (host_sock.size() < sizeof(out_sa.sun_path)) {
                        std::memcpy(out_sa.sun_path, host_sock.data(), host_sock.size());
                        out_sa.sun_path[host_sock.size()] = '\0';
                        new_len = offsetof(struct sockaddr_un, sun_path) + host_sock.size() + 1;
                    }
                }

                if (new_len > 0) {
                    uint64_t scratch = scratch_addr_below_sp(regs.sp(), sizeof(out_sa));
                    if (write_guest_mem(pid, scratch, &out_sa, static_cast<size_t>(new_len))) {
                        regs.set_arg(1, scratch);
                        regs.set_arg(2, new_len);
                        regs.store(pid);
                        proc.expecting_syscall_exit = true;
                        proc.exit_op = PendingExitOp{ExitPatchKind::kRestoreRegOnly,
                                                     1, addr_ptr, 2, addr_len, 0, 0, "", 0, ""};
                    }
                }
            }
        }
        return;
    }

    // --- 3b. getsockname/getpeername: strip host rootfs prefix from AF_UNIX sun_path ---
    if (nr == SYS_getsockname || nr == SYS_getpeername) {
        proc.expecting_syscall_exit = true;
        proc.exit_op = PendingExitOp{ExitPatchKind::kStripRootfsSockaddr,
                                     -1, 0, -1, 0, regs.arg(1), regs.arg(2), "", 0, ""};
        return;
    }

    // --- 4. getcwd: intercept exit to strip host rootfs prefix ---
    if (nr == SYS_getcwd) {
        proc.expecting_syscall_exit = true;
        proc.exit_op = PendingExitOp{ExitPatchKind::kStripRootfsGetcwd,
                                     -1, 0, -1, 0, regs.arg(0), regs.arg(1), "", 0, ""};
        return;
    }

    // --- 5. Path-Based Syscall Redirection ---
    auto rewrite_path_arg = [&](int dirfd_arg_idx, int path_arg_idx, bool follow_final,
                                ExitPatchKind exit_kind, uint64_t out_buf, uint64_t out_len) {
        std::string raw_path;
        if (!read_guest_cstring(pid, regs.arg(path_arg_idx), raw_path)) return;
        int dirfd = (dirfd_arg_idx >= 0) ? static_cast<int>(regs.arg(dirfd_arg_idx)) : AT_FDCWD;

        TranslatedPath tp = translator_.translate(pid, dirfd, raw_path, follow_final);
        if (tp.kind == PathKind::kHostPassThru) return;

        std::string target_host = tp.host_path;
        ExitPatchKind final_exit_kind = exit_kind;
        uint8_t bdom = 0;
        std::string bbacking;

        if (nr == SYS_openat && tp.kind == PathKind::kVirtualInput) {
            VInputDevice idev = VInputDevice::kTouchscreen;
            if (VInputHub::device_from_guest_path(tp.guest_path, idev)) {
                target_host = vinput_.prepare_open_path(idev);
                bdom = static_cast<uint8_t>(idev);
                final_exit_kind = ExitPatchKind::kRegisterInputFd;
            }
        } else if (nr == SYS_openat && tp.kind == PathKind::kVirtualBinder) {
            BinderDomain dom = BinderDomain::kBinder;
            if (VBinderBroker::domain_from_guest_path(tp.guest_path, dom)) {
                bbacking = vbinder_.prepare_open_backing_file(pid, dom);
                target_host = bbacking;
                bdom = static_cast<uint8_t>(dom);
                final_exit_kind = ExitPatchKind::kRegisterBinderFd;
            }
        } else if (tp.kind == PathKind::kVirtualProc || tp.kind == PathKind::kVirtualSys) {
            std::string content = pseudo_fs_.generate_content(pid, tp.guest_path, proc.creds);
            if (!content.empty()) {
                static uint32_t vseq = 0;
                std::string tmp_path = cfg_.rootfs_root + "/tmp/.vproc_" +
                                       std::to_string(static_cast<int>(pid)) + "_" +
                                       std::to_string(++vseq);
                int tfd = ::open(tmp_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
                if (tfd >= 0) {
                    (void)::write(tfd, content.data(), content.size());
                    ::close(tfd);
                    target_host = tmp_path;
                }
            }
        }

        std::string with_nul = target_host;
        with_nul.push_back('\0');
        uint64_t scratch = scratch_addr_below_sp(regs.sp(), with_nul.size());
        if (!write_guest_mem(pid, scratch, with_nul.data(), with_nul.size())) return;

        uint64_t orig_ptr = regs.arg(path_arg_idx);
        regs.set_arg(path_arg_idx, scratch);
        regs.store(pid);

        proc.expecting_syscall_exit = true;
        proc.exit_op = PendingExitOp{final_exit_kind, path_arg_idx, orig_ptr,
                                     -1, 0, out_buf, out_len, tp.guest_path, bdom, bbacking};
    };

    if (nr == SYS_openat) {
        rewrite_path_arg(0, 1, true, ExitPatchKind::kRestoreRegOnly, 0, 0);
        return;
    }
    if (nr == SYS_fstat) {
        int fd = static_cast<int>(regs.arg(0));
        uint64_t stat_buf = regs.arg(1);
        char proc_fd[128];
        std::snprintf(proc_fd, sizeof(proc_fd), "/proc/%d/fd/%d", static_cast<int>(pid), fd);
        char link_buf[4096];
        ssize_t n = ::readlink(proc_fd, link_buf, sizeof(link_buf) - 1);
        std::string gpath;
        if (n > 0) {
            link_buf[n] = '\0';
            gpath = translator_.host_to_guest(std::string_view(link_buf, static_cast<size_t>(n)));
        }
        proc.expecting_syscall_exit = true;
        proc.exit_op = PendingExitOp{ExitPatchKind::kPatchStatBuf,
                                     -1, 0, -1, 0, stat_buf, sizeof(struct stat), gpath, 0, ""};
        return;
    }
    if (nr == SYS_newfstatat) {
        int flags = static_cast<int>(regs.arg(3));
        std::string raw_path;
        if ((flags & AT_EMPTY_PATH) != 0 && read_guest_cstring(pid, regs.arg(1), raw_path) && raw_path.empty()) {
            int fd = static_cast<int>(regs.arg(0));
            char proc_fd[128];
            std::snprintf(proc_fd, sizeof(proc_fd), "/proc/%d/fd/%d", static_cast<int>(pid), fd);
            char link_buf[4096];
            ssize_t n = ::readlink(proc_fd, link_buf, sizeof(link_buf) - 1);
            std::string gpath;
            if (n > 0) {
                link_buf[n] = '\0';
                gpath = translator_.host_to_guest(std::string_view(link_buf, static_cast<size_t>(n)));
            }
            proc.expecting_syscall_exit = true;
            proc.exit_op = PendingExitOp{ExitPatchKind::kPatchStatBuf,
                                         -1, 0, -1, 0, regs.arg(2), sizeof(struct stat), gpath, 0, ""};
            return;
        }
        bool follow = (flags & AT_SYMLINK_NOFOLLOW) == 0;
        rewrite_path_arg(0, 1, follow, ExitPatchKind::kPatchStatBuf, regs.arg(2), sizeof(struct stat));
        return;
    }
#ifdef SYS_statx
    if (nr == SYS_statx) {
        bool follow = (regs.arg(2) & AT_SYMLINK_NOFOLLOW) == 0;
        rewrite_path_arg(0, 1, follow, ExitPatchKind::kPatchStatxBuf, regs.arg(4), 256);
        return;
    }
#endif
    if (nr == SYS_faccessat
#ifdef SYS_faccessat2
        || nr == SYS_faccessat2
#endif
    ) {
        rewrite_path_arg(0, 1, true, ExitPatchKind::kRestoreRegOnly, 0, 0);
        return;
    }
    if (nr == SYS_readlinkat) {
        rewrite_path_arg(0, 1, false, ExitPatchKind::kStripRootfsReadlink, regs.arg(2), regs.arg(3));
        // Even if /proc/self/fd/* was kHostPassThru, still intercept exit to strip host rootfs prefix!
        if (!proc.expecting_syscall_exit) {
            proc.expecting_syscall_exit = true;
            proc.exit_op = PendingExitOp{ExitPatchKind::kStripRootfsReadlink,
                                         -1, 0, -1, 0, regs.arg(2), regs.arg(3), "", 0, ""};
        }
        return;
    }
    if (nr == SYS_unlinkat || nr == SYS_mkdirat || nr == SYS_fchmodat || nr == SYS_utimensat) {
        rewrite_path_arg(0, 1, false, ExitPatchKind::kRestoreRegOnly, 0, 0);
        if (nr == SYS_unlinkat && !proc.exit_op.guest_path.empty()) {
            runtime_meta_.erase(proc.exit_op.guest_path);
        }
        return;
    }
    if (false
#ifdef SYS_renameat
        || nr == SYS_renameat
#endif
#ifdef SYS_renameat2
        || nr == SYS_renameat2
#endif
    ) {
        std::string raw_old, raw_new;
        if (!read_guest_cstring(pid, regs.arg(1), raw_old) ||
            !read_guest_cstring(pid, regs.arg(3), raw_new)) return;
        TranslatedPath tp_old = translator_.translate(pid, static_cast<int>(regs.arg(0)), raw_old, false);
        TranslatedPath tp_new = translator_.translate(pid, static_cast<int>(regs.arg(2)), raw_new, false);
        std::string s_old = tp_old.host_path; s_old.push_back('\0');
        std::string s_new = tp_new.host_path; s_new.push_back('\0');
        size_t total = s_old.size() + s_new.size();
        uint64_t scratch = scratch_addr_below_sp(regs.sp(), total);
        std::vector<uint8_t> blob(total);
        std::memcpy(blob.data(), s_old.data(), s_old.size());
        std::memcpy(blob.data() + s_old.size(), s_new.data(), s_new.size());
        if (!write_guest_mem(pid, scratch, blob.data(), blob.size())) return;
        uint64_t orig1 = regs.arg(1), orig3 = regs.arg(3);
        regs.set_arg(1, scratch);
        regs.set_arg(3, scratch + s_old.size());
        regs.store(pid);
        proc.expecting_syscall_exit = true;
        proc.exit_op = PendingExitOp{ExitPatchKind::kRestoreRegOnly,
                                     1, orig1, 3, orig3, 0, 0, tp_new.guest_path, 0, ""};
        return;
    }
    if (nr == SYS_chdir || nr == SYS_truncate) {
        rewrite_path_arg(-1, 0, true, ExitPatchKind::kRestoreRegOnly, 0, 0);
        return;
    }
    if (nr == SYS_execve) {
        std::string raw_path;
        if (!read_guest_cstring(pid, regs.arg(0), raw_path)) return;
        TranslatedPath tp = translator_.translate(pid, AT_FDCWD, raw_path, true);
        if (tp.kind == PathKind::kHostPassThru) return;

        // Inspect ELF64 PT_INTERP so child execve ALWAYS uses guest AOSP 12 linker64,
        // NEVER host Android 13 One UI /system/bin/linker64!
        std::string interp_guest = read_elf_interp(tp.host_path);
        TranslatedPath interp_tp;
        bool use_guest_linker = false;
        if (!interp_guest.empty()) {
            interp_tp = translator_.translate_absolute(interp_guest, true);
            if (interp_tp.host_path != tp.host_path &&
                ::access(interp_tp.host_path.c_str(), X_OK) == 0) {
                use_guest_linker = true;
            }
        }

        if (!use_guest_linker) {
            rewrite_path_arg(-1, 0, true, ExitPatchKind::kRestoreRegOnly, 0, 0);
            return;
        }

        // Read original argv[] pointers from guest memory
        std::vector<uint64_t> orig_argv;
        uint64_t argv_ptr = regs.arg(1);
        if (argv_ptr != 0) {
            for (size_t idx = 0; idx < 128; ++idx) {
                uint64_t p = 0;
                if (!read_guest_mem(pid, argv_ptr + idx * sizeof(uint64_t), &p, sizeof(p))) break;
                if (p == 0) break;
                orig_argv.push_back(p);
            }
        }

        // Build scratch block below guest SP:
        //   [linker_path\0][target_bin_path\0][8-byte aligned new_argv ptr array]
        std::string s_linker = interp_tp.host_path;
        s_linker.push_back('\0');
        TranslatedPath tp_nofollow = translator_.translate(pid, AT_FDCWD, raw_path, false);
        std::string s_bin = (tp_nofollow.kind == PathKind::kNormalRootfs && !tp_nofollow.host_path.empty())
                                ? tp_nofollow.host_path
                                : tp.host_path;
        s_bin.push_back('\0');

        size_t str_bytes = (s_linker.size() + s_bin.size() + 15u) & ~15u;
        size_t new_argc = 2 + (orig_argv.size() > 1 ? (orig_argv.size() - 1) : 0);
        size_t ptr_bytes = (new_argc + 1) * sizeof(uint64_t);
        size_t total_scratch = str_bytes + ptr_bytes;

        uint64_t scratch_base = scratch_addr_below_sp(regs.sp(), total_scratch);
        uint64_t addr_linker = scratch_base;
        uint64_t addr_bin = scratch_base + s_linker.size();
        uint64_t addr_argv = scratch_base + str_bytes;

        std::vector<uint64_t> new_argv;
        new_argv.reserve(new_argc + 1);
        new_argv.push_back(addr_linker);
        new_argv.push_back(addr_bin);
        for (size_t idx = 1; idx < orig_argv.size(); ++idx) {
            new_argv.push_back(orig_argv[idx]);
        }
        new_argv.push_back(0);

        std::vector<uint8_t> blob(total_scratch, 0);
        std::memcpy(blob.data(), s_linker.data(), s_linker.size());
        std::memcpy(blob.data() + s_linker.size(), s_bin.data(), s_bin.size());
        std::memcpy(blob.data() + str_bytes, new_argv.data(), ptr_bytes);

        if (!write_guest_mem(pid, scratch_base, blob.data(), blob.size())) return;

        uint64_t orig_arg0 = regs.arg(0);
        uint64_t orig_arg1 = regs.arg(1);
        regs.set_arg(0, addr_linker);
        regs.set_arg(1, addr_argv);
        regs.store(pid);

        proc.expecting_syscall_exit = true;
        proc.exit_op = PendingExitOp{ExitPatchKind::kRestoreRegOnly,
                                     0, orig_arg0, 1, orig_arg1, 0, 0, tp.guest_path, 0, ""};
        return;
    }
}

void Supervisor::handle_ptrace_syscall_exit(pid_t pid, ProcessState& proc) {
    PendingExitOp op = std::move(proc.exit_op);
    proc.exit_op = PendingExitOp{};

    ArchRegs regs;
    if (!regs.load(pid)) return;

    bool reg_dirty = false;
    if (op.saved_reg_index >= 0) {
        regs.set_arg(op.saved_reg_index, op.saved_reg_val);
        reg_dirty = true;
    }
    if (op.saved_reg_index2 >= 0) {
        regs.set_arg(op.saved_reg_index2, op.saved_reg_val2);
        reg_dirty = true;
    }
    if (reg_dirty) regs.store(pid);

    if (regs.ret() < 0) return;

    if (op.kind == ExitPatchKind::kRegisterInputFd) {
        vinput_.register_client_fd(pid, static_cast<int>(regs.ret()),
                                   static_cast<VInputDevice>(op.binder_domain));
        return;
    }

    if (op.kind == ExitPatchKind::kRegisterBinderFd) {
        int returned_fd = static_cast<int>(regs.ret());
        vbinder_.register_client_fd(proc.tgid, returned_fd,
                                    static_cast<BinderDomain>(op.binder_domain),
                                    op.binder_backing_path);
        return;
    }

    if (op.kind == ExitPatchKind::kPatchStatBuf && op.out_buf_addr != 0) {
        struct stat st {};
        if (read_guest_mem(pid, op.out_buf_addr, &st, sizeof(st))) {
            bool modified = false;
            if (op.guest_path.rfind("/dev/__properties__", 0) == 0) {
                // Bionic prop_area::map_prop_area() strictly requires uid==0, gid==0, mode 0644
                st.st_uid = 0;
                st.st_gid = 0;
                st.st_mode = (st.st_mode & S_IFMT) | 0644;
                modified = true;
            } else {
                auto meta = meta_db_.find(op.guest_path);
                if (meta.has_value()) {
                    st.st_uid = meta->entry->uid;
                    st.st_gid = meta->entry->gid;
                    st.st_mode = (st.st_mode & S_IFMT) | (meta->entry->mode & 07777);
                    modified = true;
                }
                auto rit = runtime_meta_.find(op.guest_path);
                if (rit != runtime_meta_.end()) {
                    if (rit->second.has_uid) {
                        st.st_uid = rit->second.uid;
                        modified = true;
                    }
                    if (rit->second.has_gid) {
                        st.st_gid = rit->second.gid;
                        modified = true;
                    }
                }
            }
            if (modified) {
                write_guest_mem(pid, op.out_buf_addr, &st, sizeof(st));
            }
        }
    } else if (op.kind == ExitPatchKind::kPatchStatxBuf && op.out_buf_addr != 0) {
#ifdef SYS_statx
        struct statx stx {};
        if (read_guest_mem(pid, op.out_buf_addr, &stx, sizeof(stx))) {
            bool modified = false;
            if (op.guest_path.rfind("/dev/__properties__", 0) == 0) {
                stx.stx_uid = 0;
                stx.stx_gid = 0;
                stx.stx_mode = static_cast<uint16_t>((stx.stx_mode & S_IFMT) | 0644);
                modified = true;
            } else {
                auto meta = meta_db_.find(op.guest_path);
                if (meta.has_value()) {
                    stx.stx_uid = meta->entry->uid;
                    stx.stx_gid = meta->entry->gid;
                    stx.stx_mode = static_cast<uint16_t>((stx.stx_mode & S_IFMT) | (meta->entry->mode & 07777));
                    modified = true;
                }
                auto rit = runtime_meta_.find(op.guest_path);
                if (rit != runtime_meta_.end()) {
                    if (rit->second.has_uid) {
                        stx.stx_uid = rit->second.uid;
                        modified = true;
                    }
                    if (rit->second.has_gid) {
                        stx.stx_gid = rit->second.gid;
                        modified = true;
                    }
                }
            }
            if (modified) {
                write_guest_mem(pid, op.out_buf_addr, &stx, sizeof(stx));
            }
        }
#endif
    } else if (op.kind == ExitPatchKind::kStripRootfsGetcwd && op.out_buf_addr != 0) {
        std::string host_cwd;
        if (read_guest_cstring(pid, op.out_buf_addr, host_cwd, op.out_buf_len)) {
            std::string guest_cwd = translator_.host_to_guest(host_cwd);
            if (guest_cwd.size() + 1 <= op.out_buf_len) {
                write_guest_mem(pid, op.out_buf_addr, guest_cwd.c_str(), guest_cwd.size() + 1);
                regs.set_ret(static_cast<int64_t>(guest_cwd.size() + 1));
                regs.store(pid);
            }
        }
    } else if (op.kind == ExitPatchKind::kStripRootfsSockaddr && op.out_buf_addr != 0 && op.out_buf_len != 0) {
        socklen_t slen = 0;
        if (read_guest_mem(pid, op.out_buf_len, &slen, sizeof(slen)) &&
            slen > offsetof(struct sockaddr_un, sun_path) &&
            slen <= sizeof(struct sockaddr_un)) {
            struct sockaddr_un sa {};
            if (read_guest_mem(pid, op.out_buf_addr, &sa, slen) && sa.sun_family == AF_UNIX) {
                size_t pbytes = slen - offsetof(struct sockaddr_un, sun_path);
                if (pbytes > 0 && sa.sun_path[0] != '\0') {
                    size_t n = ::strnlen(sa.sun_path, pbytes);
                    std::string stripped = translator_.host_to_guest(std::string_view(sa.sun_path, n));
                    if (stripped.size() < sizeof(sa.sun_path)) {
                        std::memset(sa.sun_path, 0, sizeof(sa.sun_path));
                        std::memcpy(sa.sun_path, stripped.data(), stripped.size());
                        socklen_t new_len = static_cast<socklen_t>(
                            offsetof(struct sockaddr_un, sun_path) + stripped.size() + 1);
                        write_guest_mem(pid, op.out_buf_addr, &sa, new_len);
                        write_guest_mem(pid, op.out_buf_len, &new_len, sizeof(new_len));
                    }
                }
            }
        }
    } else if (op.kind == ExitPatchKind::kStripRootfsReadlink && op.out_buf_addr != 0) {
        size_t n = static_cast<size_t>(regs.ret());
        if (n > 0 && n <= op.out_buf_len) {
            std::string val(n, '\0');
            if (read_guest_mem(pid, op.out_buf_addr, val.data(), n)) {
                std::string stripped = translator_.host_to_guest(val);
                if (stripped != val && stripped.size() <= op.out_buf_len) {
                    write_guest_mem(pid, op.out_buf_addr, stripped.data(), stripped.size());
                    regs.set_ret(static_cast<int64_t>(stripped.size()));
                    regs.store(pid);
                }
            }
        }
    }
}

int Supervisor::run_user_notif_loop(pid_t root_child, int listener_fd) {
    if (listener_fd < 0) return 1;
    registry_.get_or_create(root_child, cfg_.initial_creds);

    struct seccomp_notif req {};
    struct seccomp_notif_resp resp {};

    while (true) {
        std::memset(&req, 0, sizeof(req));
        if (::ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_RECV, &req) != 0) {
            if (errno == EINTR) continue;
            break;
        }

        std::memset(&resp, 0, sizeof(resp));
        resp.id = req.id;

        uint64_t id_check = req.id;
        if (::ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_ID_VALID, &id_check) != 0) {
            continue;
        }

        ProcessState& proc = registry_.get_or_create(static_cast<pid_t>(req.pid),
                                                     cfg_.initial_creds);
        const int nr = req.data.nr;

        if (nr == SYS_getuid)       { resp.val = proc.creds.uid; }
        else if (nr == SYS_geteuid) { resp.val = proc.creds.euid; }
        else if (nr == SYS_getgid)  { resp.val = proc.creds.gid; }
        else if (nr == SYS_getegid) { resp.val = proc.creds.egid; }
        else if (nr == SYS_setuid)  {
            proc.creds.uid = proc.creds.euid = proc.creds.suid =
                static_cast<uint32_t>(req.data.args[0]);
            resp.val = 0;
        } else if (nr == SYS_setgid) {
            proc.creds.gid = proc.creds.egid = proc.creds.sgid =
                static_cast<uint32_t>(req.data.args[0]);
            resp.val = 0;
        } else if (nr == SYS_mount || nr == SYS_umount2 || nr == SYS_chroot ||
                   nr == SYS_capset || nr == SYS_setgroups) {
            resp.val = 0;
        } else {
            resp.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
        }

        ::ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_SEND, &resp);
    }

    ::close(listener_fd);
    int status = 0;
    ::waitpid(root_child, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}

}  // namespace vguest
