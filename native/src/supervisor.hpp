#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "cred_table.hpp"
#include "path_translator.hpp"
#include "pseudo_fs.hpp"
#include "seccomp_bpf.hpp"
#include "vfs_meta_format.hpp"

namespace vguest {

struct SupervisorConfig {
    std::string rootfs_root;
    std::string meta_db_path;
    InterceptionTransport transport = InterceptionTransport::kAuto;
    VirtualCreds initial_creds;
    bool verbose = false;
};

class Supervisor {
public:
    explicit Supervisor(SupervisorConfig cfg);

    // Loads VfsMetaDb, configures PR_SET_CHILD_SUBREAPER, spawns the guest command,
    // and runs the interception loop until the guest root process exits.
    // Returns the guest's exit code (or 128+sig).
    int run(const std::vector<std::string>& guest_argv,
            const std::vector<std::string>& guest_env);

private:
    int run_ptrace_loop(pid_t root_child);
    int run_user_notif_loop(pid_t root_child, int listener_fd);

    void handle_ptrace_seccomp_entry(pid_t pid, ProcessState& proc);
    void handle_ptrace_syscall_exit(pid_t pid, ProcessState& proc);

    bool read_guest_mem(pid_t pid, uint64_t addr, void* out, size_t len) const;
    bool write_guest_mem(pid_t pid, uint64_t addr, const void* data, size_t len) const;
    bool read_guest_cstring(pid_t pid, uint64_t addr, std::string& out, size_t max_len = 4096) const;

    // Inspects an ELF64 binary on host disk for PT_INTERP (e.g. /system/bin/linker64).
    static std::string read_elf_interp(const std::string& host_binary_path);

    SupervisorConfig cfg_;
    VfsMetaDb meta_db_;
    PathTranslator translator_;
    PseudoFs pseudo_fs_;
    ProcessRegistry registry_;
};

}  // namespace vguest
