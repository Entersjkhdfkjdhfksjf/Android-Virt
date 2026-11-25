#include "vbinder.hpp"

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstddef>
#include <cstring>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

namespace vguest {

namespace {

uint64_t fd_key(pid_t pid, int fd) {
    return (static_cast<uint64_t>(static_cast<uint32_t>(pid)) << 32) |
           static_cast<uint32_t>(fd);
}

size_t align8(size_t n) { return (n + 7u) & ~7u; }

const char* domain_tag(BinderDomain d) {
    switch (d) {
        case BinderDomain::kBinder:    return "binder";
        case BinderDomain::kHwBinder:  return "hwbinder";
        case BinderDomain::kVndBinder: return "vndbinder";
    }
    return "binder";
}

}  // namespace

VBinderBroker::VBinderBroker(std::string rootfs_root, GuestMemOps mem_ops)
    : rootfs_root_(std::move(rootfs_root)), mem_ops_(std::move(mem_ops)) {
    if (rootfs_root_.size() > 1 && rootfs_root_.back() == '/') {
        rootfs_root_.pop_back();
    }
}

VBinderBroker::~VBinderBroker() {
    for (auto& dom : domains_) {
        for (auto& [pid, c] : dom.clients) {
            if (c.rx_map) {
                ::munmap(c.rx_map, kRxRingSize);
                c.rx_map = nullptr;
            }
            if (!c.backing_path.empty()) {
                ::unlink(c.backing_path.c_str());
            }
        }
    }
}

bool VBinderBroker::domain_from_guest_path(std::string_view guest_path, BinderDomain& out_domain) {
    if (guest_path == "/dev/binder") {
        out_domain = BinderDomain::kBinder;
        return true;
    }
    if (guest_path == "/dev/hwbinder") {
        out_domain = BinderDomain::kHwBinder;
        return true;
    }
    if (guest_path == "/dev/vndbinder") {
        out_domain = BinderDomain::kVndBinder;
        return true;
    }
    return false;
}

std::string VBinderBroker::prepare_open_backing_file(pid_t pid, BinderDomain domain) {
    std::string tmp_dir = rootfs_root_ + "/tmp";
    ::mkdir(tmp_dir.c_str(), 0755);

    std::string path = tmp_dir + "/.vbinder_" + domain_tag(domain) + "_" +
                       std::to_string(static_cast<int>(pid)) + "_" +
                       std::to_string(++file_seq_);
    int fd = ::open(path.c_str(), O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd >= 0) {
        (void)::ftruncate(fd, static_cast<off_t>(kRxRingSize));
        ::close(fd);
    }
    return path;
}

void VBinderBroker::register_client_fd(pid_t pid, int fd, BinderDomain domain,
                                       const std::string& backing_file_path,
                                       uint64_t explicit_mmap_base) {
    auto& dom = domains_[static_cast<size_t>(domain)];
    ClientState& client = dom.clients[pid];
    if (client.rx_map) {
        ::munmap(client.rx_map, kRxRingSize);
        client.rx_map = nullptr;
    }
    client.pid = pid;
    client.fd = fd;
    client.domain = domain;
    client.backing_path = backing_file_path;
    client.guest_mmap_base = explicit_mmap_base;
    client.rx_cursor = 0;

    int bfd = ::open(backing_file_path.c_str(), O_RDWR | O_CLOEXEC);
    if (bfd >= 0) {
        void* map = ::mmap(nullptr, kRxRingSize, PROT_READ | PROT_WRITE, MAP_SHARED, bfd, 0);
        ::close(bfd);
        if (map != MAP_FAILED) {
            client.rx_map = reinterpret_cast<uint8_t*>(map);
        }
    }
    fd_domain_map_[fd_key(pid, fd)] = domain;
}

bool VBinderBroker::is_virtual_binder_fd(pid_t pid, int fd) const {
    return fd_domain_map_.find(fd_key(pid, fd)) != fd_domain_map_.end();
}

bool VBinderBroker::handle_epoll_ctl(pid_t pid, int epfd, int op, int target_fd, uint64_t ev_ptr) {
    if (!is_virtual_binder_fd(pid, target_fd)) return false;
    uint64_t key = fd_key(pid, epfd);
    if (op == EPOLL_CTL_DEL) {
        epoll_watches_.erase(key);
        return true;
    }
    struct epoll_event ev {};
    if (ev_ptr != 0) {
        (void)mem_ops_.read(pid, ev_ptr, &ev, sizeof(ev));
    }
    epoll_watches_[key] = EpollWatch{target_fd, ev};
    return true;
}

bool VBinderBroker::is_watched_epfd(pid_t pid, int epfd) const {
    return epoll_watches_.find(fd_key(pid, epfd)) != epoll_watches_.end();
}

BinderIoctlResult VBinderBroker::handle_epoll_pwait(pid_t tgid, pid_t tid, int epfd,
                                                    uint64_t events_ptr, int maxevents) {
    BinderIoctlResult res;
    auto it = epoll_watches_.find(fd_key(tgid, epfd));
    if (it == epoll_watches_.end() || maxevents <= 0) return res;

    ClientState* client = find_client(tgid, it->second.binder_fd);
    if (!client) return res;
    res.handled = true;

    struct epoll_event ready_ev = it->second.ev;
    ready_ev.events = EPOLLIN;

    if (!client->inbox.empty()) {
        mem_ops_.write(tid, events_ptr, &ready_ev, sizeof(ready_ev));
        res.return_value = 1;
        return res;
    }

    // Park calling thread in epoll_pwait until a transaction arrives for this process
    ParkedWaiter pw;
    pw.is_epoll = true;
    pw.tgid = tgid;
    pw.pid = tid;
    pw.fd = it->second.binder_fd;
    pw.epoll_events_ptr = events_ptr;
    pw.epoll_ev = ready_ev;
    parked_[tid] = pw;
    res.park_caller = true;
    return res;
}

VBinderBroker::ClientState* VBinderBroker::find_client(pid_t pid, int fd) {
    auto it = fd_domain_map_.find(fd_key(pid, fd));
    if (it == fd_domain_map_.end()) return nullptr;
    auto& dom = domains_[static_cast<size_t>(it->second)];
    auto cit = dom.clients.find(pid);
    return (cit != dom.clients.end()) ? &cit->second : nullptr;
}

bool VBinderBroker::ensure_mmap_base(ClientState& client) {
    if (client.guest_mmap_base != 0) return true;
    if (mem_ops_.find_mmap_base && !client.backing_path.empty()) {
        client.guest_mmap_base = mem_ops_.find_mmap_base(client.pid, client.backing_path);
    }
    return client.guest_mmap_base != 0;
}

uint64_t VBinderBroker::alloc_rx_space(ClientState& client, size_t len, size_t& out_offset) {
    size_t aligned = align8(std::max<size_t>(len, 8));
    if (client.rx_cursor + aligned > kRxRingSize) {
        client.rx_cursor = 0;
    }
    if (aligned > kRxRingSize) return 0;
    out_offset = client.rx_cursor;
    client.rx_cursor += aligned;
    return client.guest_mmap_base + out_offset;
}

uint64_t VBinderBroker::get_or_create_node(DomainState& dom, pid_t owner_pid,
                                           uint64_t ptr, uint64_t cookie) {
    for (auto& [id, node] : dom.nodes) {
        if (node.owner_pid == owner_pid && node.ptr == ptr) {
            return id;
        }
    }
    uint64_t id = dom.next_node_id++;
    dom.nodes[id] = BinderNode{id, owner_pid, ptr, cookie, 1, 0};
    return id;
}

uint32_t VBinderBroker::get_or_create_handle(ClientState& client, uint64_t node_id) {
    auto it = client.node_to_handle.find(node_id);
    if (it != client.node_to_handle.end()) return it->second;
    uint32_t h = client.next_handle++;
    client.node_to_handle[node_id] = h;
    client.handle_to_node[h] = node_id;
    return h;
}

void VBinderBroker::push_br_code(ClientState& client, uint32_t br_code, pid_t target_tid) {
    PendingBrEvent ev;
    ev.bytes.resize(4);
    std::memcpy(ev.bytes.data(), &br_code, 4);
    if (target_tid != 0) {
        client.thread_inboxes[target_tid].push_back(std::move(ev));
    } else {
        client.inbox.push_back(std::move(ev));
    }
}

void VBinderBroker::push_br_payload(ClientState& client, uint32_t br_code,
                                    const void* payload, size_t len,
                                    pid_t target_tid, ReplyTarget reply_to,
                                    std::vector<PendingFdPatch> fd_patches) {
    PendingBrEvent ev;
    ev.bytes.resize(4 + len);
    std::memcpy(ev.bytes.data(), &br_code, 4);
    if (len > 0) std::memcpy(ev.bytes.data() + 4, payload, len);
    ev.reply_to = reply_to;
    ev.fd_patches = std::move(fd_patches);
    if (target_tid != 0) {
        client.thread_inboxes[target_tid].push_back(std::move(ev));
    } else {
        client.inbox.push_back(std::move(ev));
    }
}

bool VBinderBroker::flush_inbox_to_guest(ClientState& client, pid_t target_tid, uint64_t bwr_addr,
                                         binder::binder_write_read& bwr) {
    if (bwr.read_size == 0) return false;

    std::vector<uint8_t> out;
    auto apply_fd_patches = [&](const PendingBrEvent& ev) {
        if (ev.fd_patches.empty() || !client.rx_map || !mem_ops_.dup_fd_into_target) return;
        for (const auto& fp : ev.fd_patches) {
            int new_fd = mem_ops_.dup_fd_into_target(fp.sender_tgid, fp.sender_fd, target_tid);
            if (new_fd >= 0 && fp.target_rx_off + sizeof(uint32_t) <= kRxRingSize) {
                uint32_t ufd = static_cast<uint32_t>(new_fd);
                std::memcpy(client.rx_map + fp.target_rx_off, &ufd, sizeof(ufd));
            }
        }
    };

    auto wit = client.waiting_reply_depth.find(target_tid);
    bool is_waiting_reply = (wit != client.waiting_reply_depth.end() && wit->second > 0);

    // If this process owns a binder node (e.g. HIDL Waiter) or has queued process-wide
    // transactions (e.g. oneway IServiceNotification::onRegistration) with no looper thread,
    // emit BR_SPAWN_LOOPER before BR_REPLY (or after BR_TRANSACTION_COMPLETE while waiting)
    // so IPCThreadState::waitForResponse() spawns a looper thread before returning.
    auto maybe_emit_spawn_looper = [&]() {
        if ((!client.inbox.empty() || client.owns_binder_node) && client.active_loopers == 0 &&
            !client.spawn_looper_sent && client.max_threads > 0 &&
            out.size() + sizeof(uint32_t) <= bwr.read_size) {
            uint32_t spawn_cmd = binder::kBrSpawnLooper;
            const auto* sp_bytes = reinterpret_cast<const uint8_t*>(&spawn_cmd);
            out.insert(out.end(), sp_bytes, sp_bytes + sizeof(spawn_cmd));
            client.spawn_looper_sent = true;
        }
    };
    auto& tq = client.thread_inboxes[target_tid];
    while (!tq.empty()) {
        const auto& ev = tq.front();
        uint32_t ev_cmd = 0;
        if (ev.bytes.size() >= sizeof(uint32_t)) {
            std::memcpy(&ev_cmd, ev.bytes.data(), sizeof(uint32_t));
        }
        if (ev_cmd == binder::kBrReply) {
            maybe_emit_spawn_looper();
        }
        if (out.size() + ev.bytes.size() > bwr.read_size) break;
        apply_fd_patches(ev);
        if (ev.reply_to.tgid != 0) {
            client.thread_reply_stacks[target_tid].push_back(ev.reply_to);
        }
        out.insert(out.end(), ev.bytes.begin(), ev.bytes.end());
        tq.pop_front();
    }
    if (is_waiting_reply) {
        maybe_emit_spawn_looper();
    }

    // Only pull process-wide transactions/refcounts if this thread isn't actively blocked
    // waiting for a synchronous BR_REPLY. Deliver at most ONE BR_TRANSACTION per ioctl
    // (matching Linux binder.c) so thread_reply_stacks never mixes up concurrent callers.
    if (!is_waiting_reply) {
        while (!client.inbox.empty()) {
            const auto& ev = client.inbox.front();
            if (out.size() + ev.bytes.size() > bwr.read_size) break;
            uint32_t ev_cmd = 0;
            if (ev.bytes.size() >= sizeof(uint32_t)) {
                std::memcpy(&ev_cmd, ev.bytes.data(), sizeof(uint32_t));
            }
            apply_fd_patches(ev);
            if (ev.reply_to.tgid != 0) {
                client.thread_reply_stacks[target_tid].push_back(ev.reply_to);
            }
            out.insert(out.end(), ev.bytes.begin(), ev.bytes.end());
            client.inbox.pop_front();
            if (ev_cmd == binder::kBrTransaction) break;
        }
    }

    if (out.empty()) return false;

    if (!mem_ops_.write(target_tid, bwr.read_buffer, out.data(), out.size())) {
        return false;
    }
    bwr.read_consumed = out.size();
    mem_ops_.write(target_tid, bwr_addr, &bwr, sizeof(bwr));
    return true;
}

void VBinderBroker::try_wake_parked_tid(pid_t target_tid, std::vector<WakeEvent>& out_wakes) {
    auto pit = parked_.find(target_tid);
    if (pit == parked_.end()) return;

    ParkedWaiter waiter = pit->second;
    ClientState* client = find_client(waiter.tgid, waiter.fd);
    if (!client) return;

    if (waiter.is_epoll) {
        if (!client->inbox.empty() || !client->thread_inboxes[waiter.pid].empty()) {
            mem_ops_.write(waiter.pid, waiter.epoll_events_ptr,
                           &waiter.epoll_ev, sizeof(waiter.epoll_ev));
            parked_.erase(pit);
            out_wakes.push_back(WakeEvent{waiter.pid, 1});
        }
        return;
    }

    if (flush_inbox_to_guest(*client, waiter.pid, waiter.bwr_addr, waiter.bwr)) {
        parked_.erase(pit);
        out_wakes.push_back(WakeEvent{waiter.pid, 0});
    }
}

void VBinderBroker::try_wake_parked(pid_t target_tgid, std::vector<WakeEvent>& out_wakes) {
    // Prefer a parked thread that is NOT waiting for a synchronous reply
    for (int pass = 0; pass < 2; ++pass) {
        for (auto pit = parked_.begin(); pit != parked_.end(); ++pit) {
            if (pit->second.tgid != target_tgid) continue;
            ParkedWaiter waiter = pit->second;
            ClientState* client = find_client(waiter.tgid, waiter.fd);
            if (!client) continue;

            auto wit = client->waiting_reply_depth.find(waiter.pid);
            bool is_waiting = (wit != client->waiting_reply_depth.end() && wit->second > 0);
            if (pass == 0 && is_waiting) continue;

            if (waiter.is_epoll) {
                if (!client->inbox.empty() || !client->thread_inboxes[waiter.pid].empty()) {
                    mem_ops_.write(waiter.pid, waiter.epoll_events_ptr,
                                   &waiter.epoll_ev, sizeof(waiter.epoll_ev));
                    parked_.erase(pit);
                    out_wakes.push_back(WakeEvent{waiter.pid, 1});
                    return;
                }
                continue;
            }

            if (flush_inbox_to_guest(*client, waiter.pid, waiter.bwr_addr, waiter.bwr)) {
                parked_.erase(pit);
                out_wakes.push_back(WakeEvent{waiter.pid, 0});
                return;
            }
        }
    }
}

void VBinderBroker::dispatch_transaction(DomainState& dom, ClientState& sender,
                                         pid_t sender_tid,
                                         uint32_t sender_euid,
                                         const binder::binder_transaction_data& tr,
                                         bool is_reply,
                                         std::vector<WakeEvent>& out_wakes) {
    pid_t target_pid = 0;
    pid_t target_reply_tid = 0;
    uint64_t target_ptr = 0;
    uint64_t target_cookie = 0;

    if (is_reply) {
        auto& rstack = sender.thread_reply_stacks[sender_tid];
        if (rstack.empty()) {
            push_br_code(sender, binder::kBrFailedReply, sender_tid);
            return;
        }
        ReplyTarget rt = rstack.back();
        rstack.pop_back();
        target_pid = rt.tgid;
        target_reply_tid = rt.tid;
    } else {
        uint32_t handle = tr.target.handle;
        if (handle == 0) {
            target_pid = dom.context_mgr_pid;
            if (dom.context_mgr_node_id != 0) {
                auto nit = dom.nodes.find(dom.context_mgr_node_id);
                if (nit != dom.nodes.end()) {
                    target_ptr = nit->second.ptr;
                    target_cookie = nit->second.cookie;
                }
            }
        } else {
            auto hit = sender.handle_to_node.find(handle);
            if (hit != sender.handle_to_node.end()) {
                auto nit = dom.nodes.find(hit->second);
                if (nit != dom.nodes.end()) {
                    target_pid = nit->second.owner_pid;
                    target_ptr = nit->second.ptr;
                    target_cookie = nit->second.cookie;
                }
            }
        }
    }

    auto tit = dom.clients.find(target_pid);
    if (target_pid == 0 || tit == dom.clients.end() || !tit->second.rx_map ||
        !ensure_mmap_base(tit->second)) {
        push_br_code(sender, binder::kBrDeadReply, sender_tid);
        return;
    }

    ClientState& target = tit->second;

    std::vector<uint8_t> payload(static_cast<size_t>(tr.data_size));
    if (tr.data_size > 0 &&
        !mem_ops_.read(sender.pid, tr.data.ptr.buffer, payload.data(), payload.size())) {
        push_br_code(sender, binder::kBrFailedReply, sender_tid);
        return;
    }
    std::vector<uint8_t> offsets(static_cast<size_t>(tr.offsets_size));
    if (tr.offsets_size > 0 &&
        !mem_ops_.read(sender.pid, tr.data.ptr.offsets, offsets.data(), offsets.size())) {
        push_br_code(sender, binder::kBrFailedReply, sender_tid);
        return;
    }

    const size_t num_offs = offsets.size() / sizeof(binder::binder_size_t);
    std::vector<uint64_t> sg_guest_addrs(num_offs, 0);
    std::vector<size_t> sg_ring_offs(num_offs, 0);
    std::vector<size_t> sg_ring_lens(num_offs, 0);
    std::vector<binder::binder_ptr_cookie> pending_node_refs;
    std::vector<std::pair<size_t, int>> raw_fd_patches;
    std::vector<PendingFdPatch> fda_patches;
    constexpr uint32_t kBinderBufferFlagHasParent = 0x01;

    for (size_t i = 0; i < num_offs; ++i) {
        binder::binder_size_t obj_off = 0;
        std::memcpy(&obj_off, offsets.data() + i * sizeof(binder::binder_size_t), sizeof(obj_off));
        if (obj_off + sizeof(binder::binder_object_header) > payload.size()) continue;

        uint32_t obj_type = 0;
        std::memcpy(&obj_type, payload.data() + obj_off, sizeof(obj_type));

        if (obj_type == binder::kBinderTypePtr) {
            if (obj_off + sizeof(binder::binder_buffer_object) > payload.size()) continue;
            auto* bbo = reinterpret_cast<binder::binder_buffer_object*>(payload.data() + obj_off);
            size_t child_ring_off = 0;
            size_t alloc_len = static_cast<size_t>(bbo->length);
            uint64_t child_guest_ptr = alloc_rx_space(target, std::max<size_t>(alloc_len, 8), child_ring_off);
            if (child_guest_ptr == 0) {
                push_br_code(sender, binder::kBrFailedReply, sender_tid);
                return;
            }
            if (alloc_len > 0 && bbo->buffer != 0) {
                if (!mem_ops_.read(sender.pid, bbo->buffer, target.rx_map + child_ring_off, alloc_len)) {
                    push_br_code(sender, binder::kBrFailedReply, sender_tid);
                    return;
                }
            }
            bbo->buffer = child_guest_ptr;
            sg_guest_addrs[i] = child_guest_ptr;
            sg_ring_offs[i] = child_ring_off;
            sg_ring_lens[i] = alloc_len;

            if ((bbo->flags & kBinderBufferFlagHasParent) != 0 &&
                bbo->parent < i && sg_guest_addrs[bbo->parent] != 0) {
                std::memcpy(target.rx_map + sg_ring_offs[bbo->parent] + bbo->parent_offset,
                            &child_guest_ptr, sizeof(child_guest_ptr));
            }
            continue;
        }

        if (obj_type == binder::kBinderTypeFd) {
            if (obj_off + sizeof(binder::binder_fd_object) > payload.size()) continue;
            const auto* fdo = reinterpret_cast<const binder::binder_fd_object*>(payload.data() + obj_off);
            size_t fd_field_off = static_cast<size_t>(obj_off) + offsetof(binder::binder_fd_object, fd);
            raw_fd_patches.emplace_back(fd_field_off, static_cast<int>(fdo->fd));
            continue;
        }

        if (obj_type == binder::kBinderTypeFda) {
            if (obj_off + sizeof(binder::binder_fd_array_object) > payload.size()) continue;
            const auto* fda = reinterpret_cast<const binder::binder_fd_array_object*>(payload.data() + obj_off);
            if (fda->parent < i && sg_guest_addrs[fda->parent] != 0) {
                size_t parent_ring_off = sg_ring_offs[fda->parent];
                size_t parent_len = sg_ring_lens[fda->parent];
                size_t num_fds = static_cast<size_t>(fda->num_fds);
                size_t base_off = static_cast<size_t>(fda->parent_offset);
                for (size_t k = 0; k < num_fds; ++k) {
                    size_t rel_off = base_off + k * sizeof(uint32_t);
                    if (rel_off + sizeof(uint32_t) > parent_len) break;
                    size_t abs_ring_off = parent_ring_off + rel_off;
                    if (abs_ring_off + sizeof(uint32_t) > kRxRingSize) break;
                    int32_t sfd = -1;
                    std::memcpy(&sfd, target.rx_map + abs_ring_off, sizeof(sfd));
                    if (sfd >= 0) {
                        fda_patches.push_back(PendingFdPatch{sender.pid, static_cast<int>(sfd), abs_ring_off});
                    }
                }
            }
            continue;
        }

        if (obj_off + sizeof(binder::flat_binder_object) > payload.size()) continue;
        auto* obj = reinterpret_cast<binder::flat_binder_object*>(payload.data() + obj_off);
        if (obj->hdr.type == binder::kBinderTypeBinder ||
            obj->hdr.type == binder::kBinderTypeWeakBinder) {
            sender.owns_binder_node = true;
            uint64_t node_id = get_or_create_node(dom, sender.pid, obj->binder, obj->cookie);
            auto nit = dom.nodes.find(node_id);
            if (nit != dom.nodes.end() && !nit->second.driver_refs_sent) {
                nit->second.driver_refs_sent = true;
                pending_node_refs.push_back(binder::binder_ptr_cookie{obj->binder, obj->cookie});
            }
            uint32_t new_handle = get_or_create_handle(target, node_id);
            obj->hdr.type = (obj->hdr.type == binder::kBinderTypeBinder)
                                ? binder::kBinderTypeHandle
                                : binder::kBinderTypeWeakHandle;
            obj->handle = new_handle;
            obj->cookie = 0;
        } else if (obj->hdr.type == binder::kBinderTypeHandle ||
                   obj->hdr.type == binder::kBinderTypeWeakHandle) {
            uint64_t node_id = 0;
            if (obj->handle == 0) {
                node_id = dom.context_mgr_node_id;
            } else {
                auto hit = sender.handle_to_node.find(obj->handle);
                if (hit != sender.handle_to_node.end()) node_id = hit->second;
            }
            auto nit = dom.nodes.find(node_id);
            if (nit != dom.nodes.end()) {
                if (nit->second.owner_pid == target.pid) {
                    obj->hdr.type = (obj->hdr.type == binder::kBinderTypeHandle)
                                        ? binder::kBinderTypeBinder
                                        : binder::kBinderTypeWeakBinder;
                    obj->binder = nit->second.ptr;
                    obj->cookie = nit->second.cookie;
                } else {
                    obj->handle = get_or_create_handle(target, node_id);
                }
            }
        }
    }

    size_t payload_ring_off = 0;
    size_t offsets_ring_off = 0;
    uint64_t guest_payload_ptr = 0;
    uint64_t guest_offsets_ptr = 0;

    if (!payload.empty()) {
        guest_payload_ptr = alloc_rx_space(target, payload.size(), payload_ring_off);
        if (guest_payload_ptr == 0) {
            push_br_code(sender, binder::kBrFailedReply, sender_tid);
            return;
        }
        std::memcpy(target.rx_map + payload_ring_off, payload.data(), payload.size());
    }
    if (!offsets.empty()) {
        guest_offsets_ptr = alloc_rx_space(target, offsets.size(), offsets_ring_off);
        if (guest_offsets_ptr == 0) {
            push_br_code(sender, binder::kBrFailedReply, sender_tid);
            return;
        }
        std::memcpy(target.rx_map + offsets_ring_off, offsets.data(), offsets.size());
    }

    binder::binder_transaction_data out_tr {};
    out_tr.target.ptr = target_ptr;
    out_tr.cookie = target_cookie;
    out_tr.code = tr.code;
    out_tr.flags = tr.flags;
    out_tr.sender_pid = static_cast<int32_t>(sender.pid);
    out_tr.sender_euid = sender_euid;
    out_tr.data_size = tr.data_size;
    out_tr.offsets_size = tr.offsets_size;
    out_tr.data.ptr.buffer = guest_payload_ptr;
    out_tr.data.ptr.offsets = guest_offsets_ptr;

    std::vector<PendingFdPatch> fd_patches;
    fd_patches.reserve(raw_fd_patches.size() + fda_patches.size());
    for (const auto& rf : raw_fd_patches) {
        fd_patches.push_back(PendingFdPatch{sender.pid, rf.second, payload_ring_off + rf.first});
    }
    for (const auto& fp : fda_patches) {
        fd_patches.push_back(fp);
    }

    pid_t nested_target_tid = 0;
    if (is_reply) {
        auto wit = target.waiting_reply_depth.find(target_reply_tid);
        if (wit != target.waiting_reply_depth.end() && wit->second > 0) {
            wit->second--;
        }
        push_br_payload(target, binder::kBrReply, &out_tr, sizeof(out_tr), target_reply_tid,
                        ReplyTarget{0, 0}, std::move(fd_patches));
    } else {
        ReplyTarget rt {};
        if ((tr.flags & binder::kTfOneWay) == 0) {
            sender.waiting_reply_depth[sender_tid]++;
            sender.last_tx_by_tid[sender_tid] = ClientState::LastTxInfo{target.pid, tr.code, tr.flags};
            rt = ReplyTarget{sender.pid, sender_tid};
            // Re-entrant nested sync transaction (e.g. registerCallback -> onHotplug):
            // route directly to the caller thread waiting on our reply to prevent deadlock.
            auto rs_it = sender.thread_reply_stacks.find(sender_tid);
            if (rs_it != sender.thread_reply_stacks.end() && !rs_it->second.empty() &&
                rs_it->second.back().tgid == target.pid) {
                nested_target_tid = rs_it->second.back().tid;
            }
        }
        push_br_payload(target, binder::kBrTransaction, &out_tr, sizeof(out_tr),
                        nested_target_tid, rt, std::move(fd_patches));
    }

    for (const auto& pc : pending_node_refs) {
        push_br_payload(sender, binder::kBrIncrefs, &pc, sizeof(pc), sender_tid);
        push_br_payload(sender, binder::kBrAcquire, &pc, sizeof(pc), sender_tid);
    }
    push_br_code(sender, binder::kBrTransactionComplete, sender_tid);
    if (is_reply && target_reply_tid != 0) {
        try_wake_parked_tid(target_reply_tid, out_wakes);
    } else if (nested_target_tid != 0) {
        try_wake_parked_tid(nested_target_tid, out_wakes);
    } else {
        try_wake_parked(target.pid, out_wakes);
    }
}

void VBinderBroker::process_write_buffer(DomainState& dom, ClientState& sender,
                                         pid_t sender_tid,
                                         uint32_t sender_euid,
                                         const std::vector<uint8_t>& wbuf,
                                         std::vector<WakeEvent>& out_wakes) {
    size_t pos = 0;
    while (pos + 4 <= wbuf.size()) {
        uint32_t cmd = 0;
        std::memcpy(&cmd, wbuf.data() + pos, 4);
        pos += 4;

        switch (cmd) {
            case binder::kBcTransaction:
            case binder::kBcReply: {
                if (pos + sizeof(binder::binder_transaction_data) > wbuf.size()) return;
                binder::binder_transaction_data tr {};
                std::memcpy(&tr, wbuf.data() + pos, sizeof(tr));
                pos += sizeof(tr);
                dispatch_transaction(dom, sender, sender_tid, sender_euid, tr, cmd == binder::kBcReply, out_wakes);
                break;
            }
            case binder::kBcTransactionSg:
            case binder::kBcReplySg: {
                if (pos + sizeof(binder::binder_transaction_data_sg) > wbuf.size()) return;
                binder::binder_transaction_data_sg tr_sg {};
                std::memcpy(&tr_sg, wbuf.data() + pos, sizeof(tr_sg));
                pos += sizeof(tr_sg);
                dispatch_transaction(dom, sender, sender_tid, sender_euid, tr_sg.transaction_data,
                                     cmd == binder::kBcReplySg, out_wakes);
                break;
            }
            case binder::kBcFreeBuffer: {
                if (pos + sizeof(binder::binder_uintptr_t) > wbuf.size()) return;
                pos += sizeof(binder::binder_uintptr_t);
                break;
            }
            case binder::kBcIncrefs:
            case binder::kBcAcquire:
            case binder::kBcRelease:
            case binder::kBcDecrefs: {
                if (pos + sizeof(uint32_t) > wbuf.size()) return;
                uint32_t handle = 0;
                std::memcpy(&handle, wbuf.data() + pos, 4);
                pos += 4;
                auto hit = sender.handle_to_node.find(handle);
                if (hit != sender.handle_to_node.end()) {
                    auto nit = dom.nodes.find(hit->second);
                    if (nit != dom.nodes.end()) {
                        if (cmd == binder::kBcAcquire) nit->second.strong_refs++;
                        else if (cmd == binder::kBcRelease && nit->second.strong_refs > 0) nit->second.strong_refs--;
                        else if (cmd == binder::kBcIncrefs) nit->second.weak_refs++;
                        else if (cmd == binder::kBcDecrefs && nit->second.weak_refs > 0) nit->second.weak_refs--;
                    }
                }
                break;
            }
            case binder::kBcIncrefsDone:
            case binder::kBcAcquireDone: {
                if (pos + sizeof(binder::binder_ptr_cookie) > wbuf.size()) return;
                pos += sizeof(binder::binder_ptr_cookie);
                break;
            }
            case binder::kBcRegisterLooper:
            case binder::kBcEnterLooper:
                sender.active_loopers++;
                sender.spawn_looper_sent = false;
                break;
            case binder::kBcExitLooper:
                if (sender.active_loopers > 0) sender.active_loopers--;
                break;
            case binder::kBcRequestDeathNotif: {
                if (pos + sizeof(binder::binder_handle_cookie) > wbuf.size()) return;
                binder::binder_handle_cookie hc {};
                std::memcpy(&hc, wbuf.data() + pos, sizeof(hc));
                pos += sizeof(hc);
                uint64_t node_id = 0;
                if (hc.handle == 0) node_id = dom.context_mgr_node_id;
                else if (auto it = sender.handle_to_node.find(hc.handle); it != sender.handle_to_node.end()) {
                    node_id = it->second;
                }
                if (node_id != 0) {
                    dom.death_subs.push_back(DeathSubscription{sender.pid, node_id, hc.cookie});
                }
                break;
            }
            case binder::kBcClearDeathNotif: {
                if (pos + sizeof(binder::binder_handle_cookie) > wbuf.size()) return;
                binder::binder_handle_cookie hc {};
                std::memcpy(&hc, wbuf.data() + pos, sizeof(hc));
                pos += sizeof(hc);
                uint64_t node_id = 0;
                if (hc.handle == 0) node_id = dom.context_mgr_node_id;
                else if (auto it = sender.handle_to_node.find(hc.handle); it != sender.handle_to_node.end()) {
                    node_id = it->second;
                }
                dom.death_subs.erase(
                    std::remove_if(dom.death_subs.begin(), dom.death_subs.end(),
                                   [&](const DeathSubscription& s) {
                                       return s.watcher_pid == sender.pid &&
                                              (node_id == 0 || s.node_id == node_id) &&
                                              s.cookie == hc.cookie;
                                   }),
                    dom.death_subs.end());
                push_br_payload(sender, binder::kBrClearDeathNotifDone, &hc.cookie, sizeof(hc.cookie),
                                sender_tid);
                break;
            }
            case binder::kBcDeadBinderDone: {
                if (pos + sizeof(binder::binder_uintptr_t) > wbuf.size()) return;
                pos += sizeof(binder::binder_uintptr_t);
                break;
            }
            default:
                return;
        }
    }
}

BinderIoctlResult VBinderBroker::handle_ioctl(pid_t tgid, pid_t tid, int fd, unsigned long cmd,
                                              uint64_t arg_ptr, uint32_t sender_euid) {
    BinderIoctlResult res;
    ClientState* client = find_client(tgid, fd);
    if (!client) return res;
    res.handled = true;
    res.domain = client->domain;

    auto& dom = domains_[static_cast<size_t>(client->domain)];

    switch (cmd) {
        case binder::kIoctlBinderVersion: {
            binder::binder_version ver { binder::kBinderCurrentProtocolVersion };
            if (!mem_ops_.write(tid, arg_ptr, &ver, sizeof(ver))) {
                res.return_value = -EFAULT;
            }
            return res;
        }
        case binder::kIoctlBinderSetMaxThreads: {
            uint32_t max_t = 15;
            if (mem_ops_.read(tid, arg_ptr, &max_t, sizeof(max_t))) {
                client->max_threads = max_t;
            }
            return res;
        }
        case binder::kIoctlBinderSetIdleTimeout:
        case binder::kIoctlBinderSetIdlePriority:
        case binder::kIoctlBinderThreadExit:
            return res;

        case binder::kIoctlBinderSetContextMgr: {
            dom.context_mgr_pid = tgid;
            dom.context_mgr_node_id = get_or_create_node(dom, tgid, 0, 0);
            res.became_context_mgr = true;
            return res;
        }
        case binder::kIoctlBinderSetContextMgrExt: {
            binder::flat_binder_object fbo {};
            (void)mem_ops_.read(tid, arg_ptr, &fbo, sizeof(fbo));
            dom.context_mgr_pid = tgid;
            dom.context_mgr_node_id = get_or_create_node(dom, tgid, fbo.binder, fbo.cookie);
            res.became_context_mgr = true;
            return res;
        }
        case binder::kIoctlBinderWriteRead: {
            binder::binder_write_read bwr {};
            if (!mem_ops_.read(tid, arg_ptr, &bwr, sizeof(bwr))) {
                res.return_value = -EFAULT;
                return res;
            }

            if (bwr.write_size > 0) {
                std::vector<uint8_t> wbuf(static_cast<size_t>(bwr.write_size));
                if (!mem_ops_.read(tid, bwr.write_buffer, wbuf.data(), wbuf.size())) {
                    res.return_value = -EFAULT;
                    return res;
                }
                process_write_buffer(dom, *client, tid, sender_euid, wbuf, res.wakes);
                bwr.write_consumed = bwr.write_size;
            }

            if (bwr.read_size > 0) {
                if (!flush_inbox_to_guest(*client, tid, arg_ptr, bwr)) {
                    mem_ops_.write(tid, arg_ptr, &bwr, sizeof(bwr));
                    ParkedWaiter pw;
                    pw.is_epoll = false;
                    pw.tgid = tgid;
                    pw.pid = tid;
                    pw.fd = fd;
                    pw.bwr_addr = arg_ptr;
                    pw.bwr = bwr;
                    parked_[tid] = pw;
                    res.park_caller = true;
                    return res;
                }
            } else {
                mem_ops_.write(tid, arg_ptr, &bwr, sizeof(bwr));
            }
            return res;
        }
        default:
            res.return_value = -EINVAL;
            return res;
    }
}

std::vector<WakeEvent> VBinderBroker::on_process_exit(pid_t pid) {
    std::vector<WakeEvent> wakes;
    parked_.erase(pid);

    for (auto it = fd_domain_map_.begin(); it != fd_domain_map_.end(); ) {
        if (static_cast<pid_t>(it->first >> 32) == pid) it = fd_domain_map_.erase(it);
        else ++it;
    }
    for (auto it = epoll_watches_.begin(); it != epoll_watches_.end(); ) {
        if (static_cast<pid_t>(it->first >> 32) == pid) it = epoll_watches_.erase(it);
        else ++it;
    }

    for (auto& dom : domains_) {
        for (auto sit = dom.death_subs.begin(); sit != dom.death_subs.end(); ) {
            auto nit = dom.nodes.find(sit->node_id);
            if (nit != dom.nodes.end() && nit->second.owner_pid == pid) {
                auto wit = dom.clients.find(sit->watcher_pid);
                if (wit != dom.clients.end()) {
                    push_br_payload(wit->second, binder::kBrDeadBinder,
                                    &sit->cookie, sizeof(sit->cookie));
                    try_wake_parked(sit->watcher_pid, wakes);
                }
                sit = dom.death_subs.erase(sit);
            } else {
                ++sit;
            }
        }

        if (dom.context_mgr_pid == pid) {
            dom.context_mgr_pid = 0;
            dom.context_mgr_node_id = 0;
        }

        auto cit = dom.clients.find(pid);
        if (cit != dom.clients.end()) {
            if (cit->second.rx_map) ::munmap(cit->second.rx_map, kRxRingSize);
            if (!cit->second.backing_path.empty()) ::unlink(cit->second.backing_path.c_str());
            dom.clients.erase(cit);
        }
    }
    return wakes;
}


static std::string read_proc_short(const std::string& path) {
    FILE* f = std::fopen(path.c_str(), "r");
    if (!f) return "?";
    char buf[64] = {};
    size_t n = std::fread(buf, 1, sizeof(buf) - 1, f);
    std::fclose(f);
    while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r' || buf[n - 1] == '\0')) --n;
    buf[n] = '\0';
    return n > 0 ? std::string(buf) : "?";
}

void VBinderBroker::dump_state(FILE* out) const {
    if (!out) return;
    static const char* kDomNames[3] = {"binder", "hwbinder", "vndbinder"};
    bool any = false;
    for (int d = 0; d < 3; ++d) {
        for (const auto& kv : domains_[d].clients) {
            const ClientState& c = kv.second;
            bool has_wait = false;
            for (const auto& wv : c.waiting_reply_depth) {
                if (wv.second > 0) { has_wait = true; break; }
            }
            if (!has_wait && c.inbox.empty()) continue;
            if (!any) {
                std::fprintf(out, "[vbinder/diag] === Active waiters & non-empty inboxes ===\n");
                any = true;
            }
            std::string pcomm = read_proc_short("/proc/" + std::to_string(c.pid) + "/comm");
            std::fprintf(out, "[vbinder/diag] dom=%s pid=%d(%s) loopers=%d inbox=%zu owns_node=%d\n",
                         kDomNames[d], static_cast<int>(c.pid), pcomm.c_str(),
                         c.active_loopers, c.inbox.size(), c.owns_binder_node ? 1 : 0);
            for (const auto& wv : c.waiting_reply_depth) {
                if (wv.second <= 0) continue;
                pid_t tid = wv.first;
                std::string tcomm = read_proc_short("/proc/" + std::to_string(c.pid) + "/task/" +
                                                    std::to_string(tid) + "/comm");
                std::string wchan = read_proc_short("/proc/" + std::to_string(c.pid) + "/task/" +
                                                    std::to_string(tid) + "/wchan");
                bool is_parked = (parked_.find(tid) != parked_.end());
                auto txit = c.last_tx_by_tid.find(tid);
                if (txit != c.last_tx_by_tid.end()) {
                    std::string dst_comm = read_proc_short("/proc/" + std::to_string(txit->second.target_tgid) + "/comm");
                    std::fprintf(out, "  wait tid=%d(%s) depth=%d parked=%d wchan=%s -> target=%d(%s) code=%u\n",
                                 static_cast<int>(tid), tcomm.c_str(), wv.second, is_parked ? 1 : 0,
                                 wchan.c_str(), static_cast<int>(txit->second.target_tgid),
                                 dst_comm.c_str(), txit->second.code);
                } else {
                    std::fprintf(out, "  wait tid=%d(%s) depth=%d parked=%d wchan=%s\n",
                                 static_cast<int>(tid), tcomm.c_str(), wv.second, is_parked ? 1 : 0,
                                 wchan.c_str());
                }
            }
        }
    }
    if (any) std::fflush(out);
}

}  // namespace vguest
