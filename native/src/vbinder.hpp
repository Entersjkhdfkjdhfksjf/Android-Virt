#pragma once

#include <cstdint>
#include <deque>
#include <functional>
#include <string>
#include <sys/types.h>
#include <unordered_map>
#include <vector>

#include "binder_abi.hpp"

namespace vguest {

enum class BinderDomain : uint8_t {
    kBinder = 0,     // /dev/binder
    kHwBinder = 1,   // /dev/hwbinder
    kVndBinder = 2,  // /dev/vndbinder
};

// Memory-access callbacks supplied by Supervisor (or unit-test mock).
struct GuestMemOps {
    std::function<bool(pid_t, uint64_t, void*, size_t)> read;
    std::function<bool(pid_t, uint64_t, const void*, size_t)> write;
    // Discovers the guest's virtual mmap base address for a backing file path.
    std::function<uint64_t(pid_t, const std::string&)> find_mmap_base;
};

struct BinderIoctlResult {
    bool handled = false;
    bool park_caller = false;       // Caller has no BR_* events yet; park until woken
    int64_t return_value = 0;       // 0 or -errno
    std::vector<pid_t> wake_pids;   // Previously parked threads that now have BR_* data ready
};

// Isolated 3-domain user-space Binder broker substituting host /dev/*binder.
class VBinderBroker {
public:
    static constexpr size_t kRxRingSize = 1024 * 1024;  // 1 MiB per client

    VBinderBroker(std::string rootfs_root, GuestMemOps mem_ops);
    ~VBinderBroker();

    VBinderBroker(const VBinderBroker&) = delete;
    VBinderBroker& operator=(const VBinderBroker&) = delete;

    // Allocates a 1 MiB shared backing file for openat("/dev/*binder") so guest mmap() works natively.
    std::string prepare_open_backing_file(pid_t pid, BinderDomain domain);

    // Registers the FD returned by openat() so subsequent ioctl() calls route to this broker.
    void register_client_fd(pid_t pid, int fd, BinderDomain domain,
                            const std::string& backing_file_path,
                            uint64_t explicit_mmap_base = 0);

    bool is_virtual_binder_fd(pid_t pid, int fd) const;

    // Handles a trapped Binder ioctl() for (pid, fd).
    BinderIoctlResult handle_ioctl(pid_t pid, int fd, unsigned long cmd,
                                   uint64_t arg_ptr, uint32_t sender_euid);

    // Cleans up a dead guest process and delivers BR_DEAD_BINDER to registered death recipients.
    std::vector<pid_t> on_process_exit(pid_t pid);

    // Helper for domain classification from guest path.
    static bool domain_from_guest_path(std::string_view guest_path, BinderDomain& out_domain);

private:
    struct BinderNode {
        uint64_t id = 0;
        pid_t owner_pid = 0;
        uint64_t ptr = 0;
        uint64_t cookie = 0;
        uint32_t strong_refs = 1;
        uint32_t weak_refs = 0;
    };

    struct DeathSubscription {
        pid_t watcher_pid = 0;
        uint64_t node_id = 0;
        uint64_t cookie = 0;
    };

    struct PendingBrEvent {
        std::vector<uint8_t> bytes;  // Serialized [uint32_t BR_*][payload...]
    };

    struct ParkedWaiter {
        pid_t pid = 0;
        int fd = -1;
        uint64_t bwr_addr = 0;
        binder::binder_write_read bwr {};
    };

    struct ClientState {
        pid_t pid = 0;
        int fd = -1;
        BinderDomain domain = BinderDomain::kBinder;
        std::string backing_path;
        uint8_t* rx_map = nullptr;
        uint64_t guest_mmap_base = 0;
        size_t rx_cursor = 0;
        uint32_t max_threads = 15;
        uint32_t next_handle = 1;  // 0 is reserved for context manager

        std::unordered_map<uint32_t, uint64_t> handle_to_node;
        std::unordered_map<uint64_t, uint32_t> node_to_handle;
        std::deque<PendingBrEvent> inbox;
        // Stack of pending sync transaction callers awaiting our BC_REPLY
        std::deque<pid_t> reply_stack;
    };

    struct DomainState {
        pid_t context_mgr_pid = 0;
        uint64_t context_mgr_node_id = 0;
        uint64_t next_node_id = 1;
        std::unordered_map<uint64_t, BinderNode> nodes;
        std::unordered_map<pid_t, ClientState> clients;
        std::vector<DeathSubscription> death_subs;
    };

    ClientState* find_client(pid_t pid, int fd);
    bool ensure_mmap_base(ClientState& client);
    uint64_t alloc_rx_space(ClientState& client, size_t len, size_t& out_offset);
    uint64_t get_or_create_node(DomainState& dom, pid_t owner_pid, uint64_t ptr, uint64_t cookie);
    uint32_t get_or_create_handle(ClientState& client, uint64_t node_id);

    void push_br_code(ClientState& client, uint32_t br_code);
    void push_br_payload(ClientState& client, uint32_t br_code, const void* payload, size_t len);
    bool flush_inbox_to_guest(ClientState& client, uint64_t bwr_addr,
                              binder::binder_write_read& bwr);
    void try_wake_parked(pid_t target_pid, std::vector<pid_t>& out_wakes);

    void process_write_buffer(DomainState& dom, ClientState& sender, uint32_t sender_euid,
                              const std::vector<uint8_t>& wbuf,
                              std::vector<pid_t>& out_wakes);
    void dispatch_transaction(DomainState& dom, ClientState& sender, uint32_t sender_euid,
                              const binder::binder_transaction_data& tr, bool is_reply,
                              std::vector<pid_t>& out_wakes);

    std::string rootfs_root_;
    GuestMemOps mem_ops_;
    DomainState domains_[3];
    // (pid << 32 | fd) -> BinderDomain
    std::unordered_map<uint64_t, BinderDomain> fd_domain_map_;
    std::unordered_map<pid_t, ParkedWaiter> parked_;
    uint32_t file_seq_ = 0;
};

}  // namespace vguest
