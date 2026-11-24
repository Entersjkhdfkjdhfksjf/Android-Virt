#pragma once

#include <cstdint>
#include <deque>
#include <functional>
#include <string>
#include <sys/epoll.h>
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

struct GuestMemOps {
    std::function<bool(pid_t, uint64_t, void*, size_t)> read;
    std::function<bool(pid_t, uint64_t, const void*, size_t)> write;
    std::function<uint64_t(pid_t, const std::string&)> find_mmap_base;
    std::function<int(pid_t, int, pid_t)> dup_fd_into_target;
};

struct WakeEvent {
    pid_t pid = 0;
    int64_t return_value = 0;  // 0 for ioctl(BINDER_WRITE_READ), 1 for epoll_pwait
};

struct BinderIoctlResult {
    bool handled = false;
    bool park_caller = false;
    bool became_context_mgr = false;
    BinderDomain domain = BinderDomain::kBinder;
    int64_t return_value = 0;
    std::vector<WakeEvent> wakes;
};

// Isolated 3-domain user-space Binder broker substituting host /dev/*binder.
class VBinderBroker {
public:
    static constexpr size_t kRxRingSize = 1024 * 1024;  // 1 MiB per client

    VBinderBroker(std::string rootfs_root, GuestMemOps mem_ops);
    ~VBinderBroker();

    VBinderBroker(const VBinderBroker&) = delete;
    VBinderBroker& operator=(const VBinderBroker&) = delete;

    std::string prepare_open_backing_file(pid_t pid, BinderDomain domain);

    void register_client_fd(pid_t pid, int fd, BinderDomain domain,
                            const std::string& backing_file_path,
                            uint64_t explicit_mmap_base = 0);

    bool is_virtual_binder_fd(pid_t pid, int fd) const;

    // Handles epoll_ctl() on a virtual binder FD (required by Android 12 servicemanager Looper).
    bool handle_epoll_ctl(pid_t pid, int epfd, int op, int target_fd, uint64_t ev_ptr);

    // Checks if (pid, epfd) is watching a virtual binder FD.
    bool is_watched_epfd(pid_t pid, int epfd) const;

    // Handles epoll_pwait() on a watched epfd: returns 1 immediately if inbox non-empty, else parks.
    BinderIoctlResult handle_epoll_pwait(pid_t tgid, pid_t tid, int epfd,
                                         uint64_t events_ptr, int maxevents);
    BinderIoctlResult handle_epoll_pwait(pid_t pid, int epfd, uint64_t events_ptr, int maxevents) {
        return handle_epoll_pwait(pid, pid, epfd, events_ptr, maxevents);
    }

    BinderIoctlResult handle_ioctl(pid_t tgid, pid_t tid, int fd, unsigned long cmd,
                                   uint64_t arg_ptr, uint32_t sender_euid);
    BinderIoctlResult handle_ioctl(pid_t pid, int fd, unsigned long cmd,
                                   uint64_t arg_ptr, uint32_t sender_euid) {
        return handle_ioctl(pid, pid, fd, cmd, arg_ptr, sender_euid);
    }

    std::vector<WakeEvent> on_process_exit(pid_t pid);

    static bool domain_from_guest_path(std::string_view guest_path, BinderDomain& out_domain);

private:
    struct BinderNode {
        uint64_t id = 0;
        pid_t owner_pid = 0;
        uint64_t ptr = 0;
        uint64_t cookie = 0;
        uint32_t strong_refs = 1;
        uint32_t weak_refs = 0;
        bool driver_refs_sent = false;
    };

    struct DeathSubscription {
        pid_t watcher_pid = 0;
        uint64_t node_id = 0;
        uint64_t cookie = 0;
    };

    struct ReplyTarget {
        pid_t tgid = 0;
        pid_t tid = 0;
    };

    struct PendingFdPatch {
        pid_t sender_tgid = 0;
        int sender_fd = -1;
        size_t target_rx_off = 0;
    };

    struct PendingBrEvent {
        std::vector<uint8_t> bytes;
        ReplyTarget reply_to {};
        std::vector<PendingFdPatch> fd_patches;
    };

    struct ParkedWaiter {
        bool is_epoll = false;
        pid_t tgid = 0;
        pid_t pid = 0;
        int fd = -1;
        uint64_t bwr_addr = 0;
        binder::binder_write_read bwr {};
        uint64_t epoll_events_ptr = 0;
        struct epoll_event epoll_ev {};
    };

    struct EpollWatch {
        int binder_fd = -1;
        struct epoll_event ev {};
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
        int active_loopers = 0;
        bool spawn_looper_sent = false;
        uint32_t next_handle = 1;

        std::unordered_map<uint32_t, uint64_t> handle_to_node;
        std::unordered_map<uint64_t, uint32_t> node_to_handle;
        std::deque<PendingBrEvent> inbox;
        std::unordered_map<pid_t, std::deque<PendingBrEvent>> thread_inboxes;
        std::unordered_map<pid_t, std::deque<ReplyTarget>> thread_reply_stacks;
        std::unordered_map<pid_t, int> waiting_reply_depth;
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

    void push_br_code(ClientState& client, uint32_t br_code, pid_t target_tid = 0);
    void push_br_payload(ClientState& client, uint32_t br_code, const void* payload, size_t len,
                         pid_t target_tid = 0, ReplyTarget reply_to = ReplyTarget{0, 0},
                         std::vector<PendingFdPatch> fd_patches = {});
    bool flush_inbox_to_guest(ClientState& client, pid_t target_tid, uint64_t bwr_addr,
                              binder::binder_write_read& bwr);
    void try_wake_parked(pid_t target_tgid, std::vector<WakeEvent>& out_wakes);
    void try_wake_parked_tid(pid_t target_tid, std::vector<WakeEvent>& out_wakes);

    void process_write_buffer(DomainState& dom, ClientState& sender, pid_t sender_tid,
                              uint32_t sender_euid,
                              const std::vector<uint8_t>& wbuf,
                              std::vector<WakeEvent>& out_wakes);
    void dispatch_transaction(DomainState& dom, ClientState& sender, pid_t sender_tid,
                              uint32_t sender_euid,
                              const binder::binder_transaction_data& tr, bool is_reply,
                              std::vector<WakeEvent>& out_wakes);

    std::string rootfs_root_;
    GuestMemOps mem_ops_;
    DomainState domains_[3];
    std::unordered_map<uint64_t, BinderDomain> fd_domain_map_;
    // (pid << 32 | epfd) -> EpollWatch
    std::unordered_map<uint64_t, EpollWatch> epoll_watches_;
    std::unordered_map<pid_t, ParkedWaiter> parked_;
    uint32_t file_seq_ = 0;
};

}  // namespace vguest
