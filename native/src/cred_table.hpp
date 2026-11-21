#pragma once

#include <cstdint>
#include <cstdio>
#include <fstream>
#include <string>
#include <sys/types.h>
#include <unordered_map>
#include <vector>

namespace vguest {

enum class ExitPatchKind {
    kNone,
    kRestoreRegOnly,      // Restore original register(s) after rewritten path/sockaddr pointer
    kPatchStatBuf,        // Patch struct stat (newfstatat) from VfsMetaDb
    kPatchStatxBuf,       // Patch struct statx from VfsMetaDb
    kStripRootfsGetcwd,   // Rewrite getcwd() output buffer to strip host rootfs prefix
    kStripRootfsReadlink, // Rewrite readlinkat() output buffer if it leaked host rootfs
    kRegisterBinderFd,    // Register returned FD from openat("/dev/*binder") with VBinderBroker
    kRegisterInputFd,
    kStripRootfsSockaddr, // Strip rootfs prefix from getsockname/getpeername AF_UNIX sun_path     // Register returned FD from openat("/dev/input/event*") with VInputHub
};

struct PendingExitOp {
    ExitPatchKind kind = ExitPatchKind::kNone;
    int saved_reg_index = -1;
    uint64_t saved_reg_val = 0;
    int saved_reg_index2 = -1;
    uint64_t saved_reg_val2 = 0;
    uint64_t out_buf_addr = 0;
    uint64_t out_buf_len = 0;
    std::string guest_path;
    uint8_t binder_domain = 0;
    std::string binder_backing_path;
};

struct VirtualCreds {
    uint32_t uid = 0;
    uint32_t euid = 0;
    uint32_t suid = 0;
    uint32_t gid = 0;
    uint32_t egid = 0;
    uint32_t sgid = 0;
    std::vector<uint32_t> groups = {0};
    uint64_t cap_effective = 0x000001FFFFFFFFFFULL;
    uint64_t cap_permitted = 0x000001FFFFFFFFFFULL;
    uint64_t cap_inheritable = 0;
    std::string selinux_ctx = "u:r:init:s0";
};

struct ProcessState {
    pid_t pid = 0;
    pid_t tgid = 0;
    VirtualCreds creds;
    bool expecting_syscall_exit = false;
    bool parked_in_binder = false;
    PendingExitOp exit_op;
};

class ProcessRegistry {
public:
    static pid_t read_tgid_from_proc(pid_t tid) {
        char path[64];
        std::snprintf(path, sizeof(path), "/proc/%d/status", static_cast<int>(tid));
        std::ifstream in(path);
        std::string line;
        while (std::getline(in, line)) {
            if (line.rfind("Tgid:", 0) == 0) {
                try {
                    pid_t t = static_cast<pid_t>(std::stoi(line.substr(5)));
                    if (t > 0) return t;
                } catch (...) {}
                break;
            }
        }
        return tid;
    }

    ProcessState& get_or_create(pid_t pid, const VirtualCreds& default_creds) {
        auto it = procs_.find(pid);
        if (it != procs_.end()) return it->second;
        ProcessState st;
        st.pid = pid;
        st.tgid = read_tgid_from_proc(pid);
        st.creds = default_creds;
        return procs_.emplace(pid, std::move(st)).first->second;
    }

    void inherit_from_parent(pid_t parent_pid, pid_t child_pid, bool is_thread = false) {
        auto it = procs_.find(parent_pid);
        ProcessState child;
        child.pid = child_pid;
        if (it != procs_.end()) {
            child.creds = it->second.creds;
            child.tgid = is_thread ? it->second.tgid : read_tgid_from_proc(child_pid);
        } else {
            child.tgid = read_tgid_from_proc(child_pid);
        }
        procs_[child_pid] = std::move(child);
    }

    bool has_tgid(pid_t tgid) const noexcept {
        for (const auto& kv : procs_) {
            if (kv.second.tgid == tgid) return true;
        }
        return false;
    }

    void erase(pid_t pid) { procs_.erase(pid); }
    bool empty() const noexcept { return procs_.empty(); }
    size_t size() const noexcept { return procs_.size(); }

private:
    std::unordered_map<pid_t, ProcessState> procs_;
};

}  // namespace vguest
