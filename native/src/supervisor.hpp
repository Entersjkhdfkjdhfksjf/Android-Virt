#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "cred_table.hpp"
#include "path_translator.hpp"
#include "prop_service.hpp"
#include "pseudo_fs.hpp"
#include "seccomp_bpf.hpp"
#include "vbinder.hpp"
#include "vinput.hpp"
#include "vfs_meta_format.hpp"

namespace vguest {

struct SupervisorConfig {
    std::string rootfs_root;
    std::string meta_db_path;
    InterceptionTransport transport = InterceptionTransport::kAuto;
    VirtualCreds initial_creds;
    bool enable_property_service = true;
    bool verbose = false;
};

class Supervisor {
public:
    explicit Supervisor(SupervisorConfig cfg);

    int run(const std::vector<std::string>& guest_argv,
            const std::vector<std::string>& guest_env);

private:
    int run_ptrace_loop(pid_t root_child);
    int run_user_notif_loop(pid_t root_child, int listener_fd);

    void handle_ptrace_seccomp_entry(pid_t pid, ProcessState& proc);
    void handle_ptrace_syscall_exit(pid_t pid, ProcessState& proc);
    void wake_parked_binder_threads(const std::vector<WakeEvent>& wakes);

    bool read_guest_mem(pid_t pid, uint64_t addr, void* out, size_t len) const;
    bool write_guest_mem(pid_t pid, uint64_t addr, const void* data, size_t len) const;
    bool read_guest_cstring(pid_t pid, uint64_t addr, std::string& out, size_t max_len = 4096) const;
    static uint64_t find_guest_mmap_base(pid_t pid, const std::string& path_substr);
    static std::string read_elf_interp(const std::string& host_binary_path);

    SupervisorConfig cfg_;
    VfsMetaDb meta_db_;
    PathTranslator translator_;
    PseudoFs pseudo_fs_;
    PropertyService prop_service_;
    VBinderBroker vbinder_;
    VInputHub vinput_;
    ProcessRegistry registry_;
};

}  // namespace vguest
