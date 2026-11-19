#include "vbinder.hpp"

#include <algorithm>
#include <cerrno>
#include <cstdio>
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
        // Wrap ring cursor for long-running services
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

void VBinderBroker::push_br_code(ClientState& client, uint32_t br_code) {
    PendingBrEvent ev;
    ev.bytes.resize(4);
    std::memcpy(ev.bytes.data(), &br_code, 4);
    client.inbox.push_back(std::move(ev));
}

void VBinderBroker::push_br_payload(ClientState& client, uint32_t br_code,
                                    const void* payload, size_t len) {
    PendingBrEvent ev;
    ev.bytes.resize(4 + len);
    std::memcpy(ev.bytes.data(), &br_code, 4);
    if (len > 0) std::memcpy(ev.bytes.data() + 4, payload, len);
    client.inbox.push_back(std::move(ev));
}

bool VBinderBroker::flush_inbox_to_guest(ClientState& client, uint64_t bwr_addr,
                                         binder::binder_write_read& bwr) {
    if (bwr.read_size == 0 || client.inbox.empty()) return false;

    std::vector<uint8_t> out;
    while (!client.inbox.empty()) {
        const auto& ev = client.inbox.front();
        if (out.size() + ev.bytes.size() > bwr.read_size) break;
        out.insert(out.end(), ev.bytes.begin(), ev.bytes.end());
        client.inbox.pop_front();
    }
    if (out.empty()) return false;

    if (!mem_ops_.write(client.pid, bwr.read_buffer, out.data(), out.size())) {
        return false;
    }
    bwr.read_consumed = out.size();
    mem_ops_.write(client.pid, bwr_addr, &bwr, sizeof(bwr));
    return true;
}

void VBinderBroker::try_wake_parked(pid_t target_pid, std::vector<pid_t>& out_wakes) {
    auto pit = parked_.find(target_pid);
    if (pit == parked_.end()) return;

    ParkedWaiter waiter = pit->second;
    ClientState* client = find_client(waiter.pid, waiter.fd);
    if (!client) return;

    if (flush_inbox_to_guest(*client, waiter.bwr_addr, waiter.bwr)) {
        parked_.erase(pit);
        out_wakes.push_back(target_pid);
    }
}

void VBinderBroker::dispatch_transaction(DomainState& dom, ClientState& sender,
                                         uint32_t sender_euid,
                                         const binder::binder_transaction_data& tr,
                                         bool is_reply,
                                         std::vector<pid_t>& out_wakes) {
    pid_t target_pid = 0;
    uint64_t target_ptr = 0;
    uint64_t target_cookie = 0;

    if (is_reply) {
        if (sender.reply_stack.empty()) {
            push_br_code(sender, binder::kBrFailedReply);
            return;
        }
        target_pid = sender.reply_stack.back();
        sender.reply_stack.pop_back();
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
        push_br_code(sender, binder::kBrDeadReply);
        return;
    }

    ClientState& target = tit->second;

    // Copy transaction payload & offsets from sender's address space
    std::vector<uint8_t> payload(static_cast<size_t>(tr.data_size));
    if (tr.data_size > 0 &&
        !mem_ops_.read(sender.pid, tr.data.ptr.buffer, payload.data(), payload.size())) {
        push_br_code(sender, binder::kBrFailedReply);
        return;
    }
    std::vector<uint8_t> offsets(static_cast<size_t>(tr.offsets_size));
    if (tr.offsets_size > 0 &&
        !mem_ops_.read(sender.pid, tr.data.ptr.offsets, offsets.data(), offsets.size())) {
        push_br_code(sender, binder::kBrFailedReply);
        return;
    }

    // Translate flat_binder_object entries inside payload (BINDER <-> HANDLE)
    const size_t num_offs = offsets.size() / sizeof(binder::binder_size_t);
    for (size_t i = 0; i < num_offs; ++i) {
        binder::binder_size_t obj_off = 0;
        std::memcpy(&obj_off, offsets.data() + i * sizeof(binder::binder_size_t), sizeof(obj_off));
        if (obj_off + sizeof(binder::flat_binder_object) > payload.size()) continue;

        auto* obj = reinterpret_cast<binder::flat_binder_object*>(payload.data() + obj_off);
        if (obj->hdr.type == binder::kBinderTypeBinder ||
            obj->hdr.type == binder::kBinderTypeWeakBinder) {
            uint64_t node_id = get_or_create_node(dom, sender.pid, obj->binder, obj->cookie);
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

    // Write payload + offsets directly into target's shared RX memfd ring
    size_t payload_ring_off = 0;
    size_t offsets_ring_off = 0;
    uint64_t guest_payload_ptr = 0;
    uint64_t guest_offsets_ptr = 0;

    if (!payload.empty()) {
        guest_payload_ptr = alloc_rx_space(target, payload.size(), payload_ring_off);
        if (guest_payload_ptr == 0) {
            push_br_code(sender, binder::kBrFailedReply);
            return;
        }
        std::memcpy(target.rx_map + payload_ring_off, payload.data(), payload.size());
    }
    if (!offsets.empty()) {
        guest_offsets_ptr = alloc_rx_space(target, offsets.size(), offsets_ring_off);
        if (guest_offsets_ptr == 0) {
            push_br_code(sender, binder::kBrFailedReply);
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

    if (is_reply) {
        push_br_payload(target, binder::kBrReply, &out_tr, sizeof(out_tr));
    } else {
        if ((tr.flags & binder::kTfOneWay) == 0) {
            target.reply_stack.push_back(sender.pid);
        }
        push_br_payload(target, binder::kBrTransaction, &out_tr, sizeof(out_tr));
    }

    push_br_code(sender, binder::kBrTransactionComplete);
    try_wake_parked(target.pid, out_wakes);
}

void VBinderBroker::process_write_buffer(DomainState& dom, ClientState& sender,
                                         uint32_t sender_euid,
                                         const std::vector<uint8_t>& wbuf,
                                         std::vector<pid_t>& out_wakes) {
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
                dispatch_transaction(dom, sender, sender_euid, tr, cmd == binder::kBcReply, out_wakes);
                break;
            }
            case binder::kBcTransactionSg:
            case binder::kBcReplySg: {
                if (pos + sizeof(binder::binder_transaction_data_sg) > wbuf.size()) return;
                binder::binder_transaction_data_sg tr_sg {};
                std::memcpy(&tr_sg, wbuf.data() + pos, sizeof(tr_sg));
                pos += sizeof(tr_sg);
                dispatch_transaction(dom, sender, sender_euid, tr_sg.transaction_data,
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
            case binder::kBcExitLooper:
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
                push_br_payload(sender, binder::kBrClearDeathNotifDone, &hc.cookie, sizeof(hc.cookie));
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

BinderIoctlResult VBinderBroker::handle_ioctl(pid_t pid, int fd, unsigned long cmd,
                                              uint64_t arg_ptr, uint32_t sender_euid) {
    BinderIoctlResult res;
    ClientState* client = find_client(pid, fd);
    if (!client) return res;
    res.handled = true;

    auto& dom = domains_[static_cast<size_t>(client->domain)];

    switch (cmd) {
        case binder::kIoctlBinderVersion: {
            binder::binder_version ver { binder::kBinderCurrentProtocolVersion };
            if (!mem_ops_.write(pid, arg_ptr, &ver, sizeof(ver))) {
                res.return_value = -EFAULT;
            }
            return res;
        }
        case binder::kIoctlBinderSetMaxThreads: {
            uint32_t max_t = 15;
            if (mem_ops_.read(pid, arg_ptr, &max_t, sizeof(max_t))) {
                client->max_threads = max_t;
            }
            return res;
        }
        case binder::kIoctlBinderSetIdleTimeout:
        case binder::kIoctlBinderSetIdlePriority:
        case binder::kIoctlBinderThreadExit:
            return res;

        case binder::kIoctlBinderSetContextMgr: {
            dom.context_mgr_pid = pid;
            dom.context_mgr_node_id = get_or_create_node(dom, pid, 0, 0);
            return res;
        }
        case binder::kIoctlBinderSetContextMgrExt: {
            binder::flat_binder_object fbo {};
            (void)mem_ops_.read(pid, arg_ptr, &fbo, sizeof(fbo));
            dom.context_mgr_pid = pid;
            dom.context_mgr_node_id = get_or_create_node(dom, pid, fbo.binder, fbo.cookie);
            return res;
        }
        case binder::kIoctlBinderWriteRead: {
            binder::binder_write_read bwr {};
            if (!mem_ops_.read(pid, arg_ptr, &bwr, sizeof(bwr))) {
                res.return_value = -EFAULT;
                return res;
            }

            if (bwr.write_size > 0) {
                std::vector<uint8_t> wbuf(static_cast<size_t>(bwr.write_size));
                if (!mem_ops_.read(pid, bwr.write_buffer, wbuf.data(), wbuf.size())) {
                    res.return_value = -EFAULT;
                    return res;
                }
                process_write_buffer(dom, *client, sender_euid, wbuf, res.wake_pids);
                bwr.write_consumed = bwr.write_size;
            }

            if (bwr.read_size > 0) {
                if (!flush_inbox_to_guest(*client, arg_ptr, bwr)) {
                    // No BR_* events ready yet -> write updated write_consumed and park thread
                    mem_ops_.write(pid, arg_ptr, &bwr, sizeof(bwr));
                    parked_[pid] = ParkedWaiter{pid, fd, arg_ptr, bwr};
                    res.park_caller = true;
                    return res;
                }
            } else {
                mem_ops_.write(pid, arg_ptr, &bwr, sizeof(bwr));
            }
            return res;
        }
        default:
            res.return_value = -EINVAL;
            return res;
    }
}

std::vector<pid_t> VBinderBroker::on_process_exit(pid_t pid) {
    std::vector<pid_t> wakes;
    parked_.erase(pid);

    for (auto it = fd_domain_map_.begin(); it != fd_domain_map_.end(); ) {
        if (static_cast<pid_t>(it->first >> 32) == pid) {
            it = fd_domain_map_.erase(it);
        } else {
            ++it;
        }
    }

    for (auto& dom : domains_) {
        // Notify death recipients watching any node owned by `pid`
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

}  // namespace vguest
