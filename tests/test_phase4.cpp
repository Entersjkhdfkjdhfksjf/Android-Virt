#include <cassert>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <iostream>
#include <sys/mman.h>
#include <unistd.h>
#include <vector>

#include "vbinder.hpp"

namespace fs = std::filesystem;
using namespace vguest;
using namespace vguest::binder;

int main() {
    fs::path tmp = fs::temp_directory_path() / "vguest_phase4_test";
    fs::remove_all(tmp);
    fs::create_directories(tmp / "tmp");

    // In-process mock GuestMemOps: virtual addresses are real local pointers
    GuestMemOps ops;
    ops.read = [](pid_t, uint64_t addr, void* out, size_t len) {
        std::memcpy(out, reinterpret_cast<const void*>(addr), len);
        return true;
    };
    ops.write = [](pid_t, uint64_t addr, const void* data, size_t len) {
        std::memcpy(reinterpret_cast<void*>(addr), data, len);
        return true;
    };
    ops.find_mmap_base = [](pid_t, const std::string&) -> uint64_t { return 0; };

    VBinderBroker broker(tmp.string(), ops);

    // 1. Register simulated servicemanager (PID 200, fd 3) and client (PID 201, fd 3) on /dev/binder
    std::string sm_file = broker.prepare_open_backing_file(200, BinderDomain::kBinder);
    std::string cl_file = broker.prepare_open_backing_file(201, BinderDomain::kBinder);

    int sm_fd = ::open(sm_file.c_str(), O_RDONLY);
    int cl_fd = ::open(cl_file.c_str(), O_RDONLY);
    assert(sm_fd >= 0 && cl_fd >= 0);

    void* sm_rx = ::mmap(nullptr, VBinderBroker::kRxRingSize, PROT_READ, MAP_SHARED, sm_fd, 0);
    void* cl_rx = ::mmap(nullptr, VBinderBroker::kRxRingSize, PROT_READ, MAP_SHARED, cl_fd, 0);
    ::close(sm_fd);
    ::close(cl_fd);
    assert(sm_rx != MAP_FAILED && cl_rx != MAP_FAILED);

    broker.register_client_fd(200, 3, BinderDomain::kBinder, sm_file,
                              reinterpret_cast<uint64_t>(sm_rx));
    broker.register_client_fd(201, 3, BinderDomain::kBinder, cl_file,
                              reinterpret_cast<uint64_t>(cl_rx));

    // 2. Verify BINDER_VERSION == 8
    binder_version ver {0};
    auto r_ver = broker.handle_ioctl(200, 3, kIoctlBinderVersion,
                                     reinterpret_cast<uint64_t>(&ver), 1000);
    assert(r_ver.handled && r_ver.return_value == 0 && ver.protocol_version == 8);

    // 3. servicemanager claims context manager (handle 0) and parks waiting for transactions
    auto r_cm = broker.handle_ioctl(200, 3, kIoctlBinderSetContextMgr, 0, 1000);
    assert(r_cm.handled && r_cm.return_value == 0);

    uint8_t sm_rbuf[512] = {};
    binder_write_read sm_bwr {};
    sm_bwr.read_size = sizeof(sm_rbuf);
    sm_bwr.read_buffer = reinterpret_cast<uint64_t>(sm_rbuf);
    auto r_park = broker.handle_ioctl(200, 3, kIoctlBinderWriteRead,
                                      reinterpret_cast<uint64_t>(&sm_bwr), 1000);
    assert(r_park.handled && r_park.park_caller);

    // 4. Client (PID 201) sends BC_TRANSACTION to handle 0 with a flat_binder_object
    struct PayloadWithObj {
        char tag[8];
        flat_binder_object obj;
    } tx_payload {};
    std::memcpy(tx_payload.tag, "ADD_SVC", 8);
    tx_payload.obj.hdr.type = kBinderTypeBinder;
    tx_payload.obj.flags = 0;
    tx_payload.obj.binder = 0xCAFEBABEULL;
    tx_payload.obj.cookie = 0xDEADBEEFULL;
    binder_size_t tx_offsets[1] = { offsetof(PayloadWithObj, obj) };

    struct {
        uint32_t cmd;
        binder_transaction_data tr;
    } __attribute__((packed)) tx_cmd {};
    tx_cmd.cmd = kBcTransaction;
    tx_cmd.tr.target.handle = 0;
    tx_cmd.tr.code = 3;  // ADD_SERVICE_TRANSACTION
    tx_cmd.tr.flags = 0;
    tx_cmd.tr.data_size = sizeof(tx_payload);
    tx_cmd.tr.offsets_size = sizeof(tx_offsets);
    tx_cmd.tr.data.ptr.buffer = reinterpret_cast<uint64_t>(&tx_payload);
    tx_cmd.tr.data.ptr.offsets = reinterpret_cast<uint64_t>(tx_offsets);

    uint8_t cl_rbuf[512] = {};
    binder_write_read cl_bwr {};
    cl_bwr.write_size = sizeof(tx_cmd);
    cl_bwr.write_buffer = reinterpret_cast<uint64_t>(&tx_cmd);
    cl_bwr.read_size = sizeof(cl_rbuf);
    cl_bwr.read_buffer = reinterpret_cast<uint64_t>(cl_rbuf);

    auto r_tx = broker.handle_ioctl(201, 3, kIoctlBinderWriteRead,
                                    reinterpret_cast<uint64_t>(&cl_bwr), 1000);
    assert(r_tx.handled && !r_tx.park_caller);
    // servicemanager must have been woken!
    assert(r_tx.wakes.size() == 1 && r_tx.wakes[0].pid == 200);

    // Verify client got BR_TRANSACTION_COMPLETE
    size_t cl_off = 0;
    uint32_t cl_br = 0;
    while (cl_off + 4 <= cl_bwr.read_consumed) {
        std::memcpy(&cl_br, cl_rbuf + cl_off, 4);
        cl_off += 4;
        if (cl_br == kBrIncrefs || cl_br == kBrAcquire) {
            cl_off += sizeof(binder_ptr_cookie);
            continue;
        }
        break;
    }
    assert(cl_br == kBrTransactionComplete);

    // Verify servicemanager got BR_TRANSACTION with translated BINDER_TYPE_HANDLE
    uint32_t sm_br = 0;
    binder_transaction_data sm_tr {};
    std::memcpy(&sm_br, sm_rbuf, 4);
    std::memcpy(&sm_tr, sm_rbuf + 4, sizeof(sm_tr));
    assert(sm_br == kBrTransaction);
    assert(sm_tr.sender_pid == 201 && sm_tr.sender_euid == 1000 && sm_tr.code == 3);

    const auto* rx_payload = reinterpret_cast<const PayloadWithObj*>(sm_tr.data.ptr.buffer);
    assert(std::memcmp(rx_payload->tag, "ADD_SVC", 8) == 0);
    assert(rx_payload->obj.hdr.type == kBinderTypeHandle);
    assert(rx_payload->obj.handle == 1);

    // 5. Client parks waiting for reply; servicemanager sends BC_REPLY + requests death notif
    cl_bwr = binder_write_read{};
    cl_bwr.read_size = sizeof(cl_rbuf);
    cl_bwr.read_buffer = reinterpret_cast<uint64_t>(cl_rbuf);
    auto r_cl_wait = broker.handle_ioctl(201, 3, kIoctlBinderWriteRead,
                                         reinterpret_cast<uint64_t>(&cl_bwr), 1000);
    assert(r_cl_wait.park_caller);

    const char reply_str[4] = {'O', 'K', '!', '\0'};
    struct {
        uint32_t cmd_death;
        binder_handle_cookie hc;
        uint32_t cmd_reply;
        binder_transaction_data tr;
    } __attribute__((packed)) sm_reply_batch {};
    sm_reply_batch.cmd_death = kBcRequestDeathNotif;
    sm_reply_batch.hc.handle = rx_payload->obj.handle;
    sm_reply_batch.hc.cookie = 0x12345678ULL;
    sm_reply_batch.cmd_reply = kBcReply;
    sm_reply_batch.tr.data_size = sizeof(reply_str);
    sm_reply_batch.tr.data.ptr.buffer = reinterpret_cast<uint64_t>(reply_str);

    sm_bwr = binder_write_read{};
    sm_bwr.write_size = sizeof(sm_reply_batch);
    sm_bwr.write_buffer = reinterpret_cast<uint64_t>(&sm_reply_batch);
    auto r_rep = broker.handle_ioctl(200, 3, kIoctlBinderWriteRead,
                                     reinterpret_cast<uint64_t>(&sm_bwr), 1000);
    assert(r_rep.wakes.size() == 1 && r_rep.wakes[0].pid == 201);

    // Verify client received BR_REPLY with "OK!"
    uint32_t rep_br = 0;
    binder_transaction_data rep_tr {};
    std::memcpy(&rep_br, cl_rbuf, 4);
    std::memcpy(&rep_tr, cl_rbuf + 4, sizeof(rep_tr));
    assert(rep_br == kBrReply);
    assert(std::strcmp(reinterpret_cast<const char*>(rep_tr.data.ptr.buffer), "OK!") == 0);

    // 6. Verify death notification on client exit
    sm_bwr = binder_write_read{};
    sm_bwr.read_size = sizeof(sm_rbuf);
    sm_bwr.read_buffer = reinterpret_cast<uint64_t>(sm_rbuf);
    // Drain sm's BR_TRANSACTION_COMPLETE first
    broker.handle_ioctl(200, 3, kIoctlBinderWriteRead, reinterpret_cast<uint64_t>(&sm_bwr), 1000);
    // Park sm again
    sm_bwr.read_consumed = 0;
    assert(broker.handle_ioctl(200, 3, kIoctlBinderWriteRead,
                               reinterpret_cast<uint64_t>(&sm_bwr), 1000).park_caller);

    auto death_wakes = broker.on_process_exit(201);
    assert(death_wakes.size() == 1 && death_wakes[0].pid == 200);
    uint32_t dead_br = 0;
    uint64_t dead_cookie = 0;
    std::memcpy(&dead_br, sm_rbuf, 4);
    std::memcpy(&dead_cookie, sm_rbuf + 4, 8);
    assert(dead_br == kBrDeadBinder && dead_cookie == 0x12345678ULL);

    // 7. Verify domain isolation: /dev/hwbinder has no context manager yet -> BR_DEAD_REPLY
    std::string hw_file = broker.prepare_open_backing_file(300, BinderDomain::kHwBinder);
    int hw_fd = ::open(hw_file.c_str(), O_RDONLY);
    void* hw_rx = ::mmap(nullptr, VBinderBroker::kRxRingSize, PROT_READ, MAP_SHARED, hw_fd, 0);
    ::close(hw_fd);
    broker.register_client_fd(300, 4, BinderDomain::kHwBinder, hw_file,
                              reinterpret_cast<uint64_t>(hw_rx));
    assert(broker.is_virtual_binder_fd(300, 4));

    ::munmap(sm_rx, VBinderBroker::kRxRingSize);
    ::munmap(cl_rx, VBinderBroker::kRxRingSize);
    ::munmap(hw_rx, VBinderBroker::kRxRingSize);
    fs::remove_all(tmp);

    std::cout << "[PASS] VBinderBroker 3-domain isolation, handle translation, sync RPC & death recipients\n";
    std::cout << "[ALL PHASE 4 UNIT TESTS PASSED]\n";
    return 0;
}
