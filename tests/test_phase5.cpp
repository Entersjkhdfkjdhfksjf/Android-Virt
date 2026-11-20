#include <cassert>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <linux/input.h>
#include <sys/ioctl.h>
#include <vector>

#include "vinput.hpp"
#include "virt_fb_protocol.hpp"

namespace fs = std::filesystem;

static void test_triple_buffer_ring() {
    const uint32_t W = 320, H = 200;
    size_t total = vguest::fb::compute_ring_total_size(W, H);
    std::vector<uint8_t> mem(total, 0);

    auto* hdr = reinterpret_cast<vguest::fb::VirtFbHeader*>(mem.data());
    vguest::fb::init_fb_header(hdr, W, H);
    assert(std::memcmp(hdr->magic, "VGFB", 4) == 0);
    assert(hdr->width == W && hdr->height == H);

    // Producer writes frame 1
    int ws = vguest::fb::acquire_write_slot(hdr);
    assert(ws == 0);
    uint8_t* p0 = vguest::fb::slot_pixel_ptr(mem.data(), hdr, static_cast<uint32_t>(ws));
    std::memset(p0, 0xAB, W * H * 4);
    vguest::fb::present_write_slot(hdr, static_cast<uint32_t>(ws));
    assert(hdr->frame_seq.load() == 1);

    // Consumer acquires frame 1
    int rs = vguest::fb::acquire_ready_slot(hdr);
    assert(rs == 0);
    uint8_t* rp = vguest::fb::slot_pixel_ptr(mem.data(), hdr, static_cast<uint32_t>(rs));
    assert(rp[0] == 0xAB);

    // Producer can acquire slot 1 while consumer displays slot 0 (zero tearing!)
    int ws2 = vguest::fb::acquire_write_slot(hdr);
    assert(ws2 == 1);
    vguest::fb::present_write_slot(hdr, static_cast<uint32_t>(ws2));
    vguest::fb::release_display_slot(hdr, static_cast<uint32_t>(rs));

    int rs2 = vguest::fb::acquire_ready_slot(hdr);
    assert(rs2 == 1);
    vguest::fb::release_display_slot(hdr, static_cast<uint32_t>(rs2));

    std::cout << "[PASS] VirtFbHeader triple-buffered shared-memory ring\n";
}

static void test_vinput_evdev_ioctls() {
    fs::path tmp = fs::temp_directory_path() / "vguest_phase5_input_test";
    fs::remove_all(tmp);
    fs::create_directories(tmp);

    vguest::InputMemOps ops;
    ops.write = [](pid_t, uint64_t addr, const void* data, size_t len) {
        std::memcpy(reinterpret_cast<void*>(addr), data, len);
        return true;
    };

    vguest::VInputHub hub(tmp.string(), 1400, 876, ops);
    assert(hub.start());
    hub.register_client_fd(500, 7, vguest::VInputDevice::kTouchscreen);
    hub.register_client_fd(500, 8, vguest::VInputDevice::kStylus);

    char name[64] = {};
    assert(hub.handle_ioctl(500, 7, EVIOCGNAME(sizeof(name)),
                            reinterpret_cast<uint64_t>(name)) > 0);
    assert(std::strcmp(name, "vguest_multitouch_screen") == 0);

    std::memset(name, 0, sizeof(name));
    assert(hub.handle_ioctl(500, 8, EVIOCGNAME(sizeof(name)),
                            reinterpret_cast<uint64_t>(name)) > 0);
    assert(std::strcmp(name, "vguest_spen_digitizer") == 0);

    struct input_absinfo abs_x {};
    assert(hub.handle_ioctl(500, 8, EVIOCGABS(ABS_X),
                            reinterpret_cast<uint64_t>(&abs_x)) == 0);
    assert(abs_x.maximum == 1399);

    struct input_absinfo abs_p {};
    assert(hub.handle_ioctl(500, 8, EVIOCGABS(ABS_PRESSURE),
                            reinterpret_cast<uint64_t>(&abs_p)) == 0);
    assert(abs_p.maximum == 4096);

    hub.stop();
    fs::remove_all(tmp);
    std::cout << "[PASS] VInputHub multi-touch & S Pen evdev ioctl emulation\n";
}

int main() {
    test_triple_buffer_ring();
    test_vinput_evdev_ioctls();
    std::cout << "[ALL PHASE 5 UNIT TESTS PASSED]\n";
    return 0;
}
