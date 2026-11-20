#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <linux/input.h>
#include <string>
#include <string_view>
#include <sys/types.h>
#include <thread>
#include <unordered_map>

namespace vguest {

enum class VInputDevice : uint8_t {
    kTouchscreen = 0,  // /dev/input/event0 (Multi-touch)
    kStylus      = 1,  // /dev/input/event1 (Samsung S Pen digitizer)
};

// Packet sent from Host JNI over AF_UNIX SOCK_DGRAM to <rootfs>/dev/socket/vguest_input
struct HostInputPacket {
    uint32_t dev_idx;   // 0 = touchscreen, 1 = stylus
    uint16_t type;      // EV_ABS / EV_KEY / EV_SYN
    uint16_t code;      // ABS_MT_POSITION_X, BTN_TOUCH, BTN_TOOL_PEN, etc.
    int32_t value;
};
static_assert(sizeof(HostInputPacket) == 12, "HostInputPacket must be 12 bytes");

struct InputMemOps {
    std::function<bool(pid_t, uint64_t, const void*, size_t)> write;
};

// Virtual Linux evdev hub emulating /dev/input/event0 (Touch) and /dev/input/event1 (S Pen).
class VInputHub {
public:
    VInputHub(std::string rootfs_root, uint32_t screen_w, uint32_t screen_h, InputMemOps mem_ops);
    ~VInputHub();

    VInputHub(const VInputHub&) = delete;
    VInputHub& operator=(const VInputHub&) = delete;

    // Creates <rootfs>/dev/socket/vguest_input + backing FIFOs and starts host-input bridge thread.
    bool start();
    void stop();

    // Returns host backing FIFO path for guest openat("/dev/input/event0" or "event1").
    std::string prepare_open_path(VInputDevice dev) const;

    void register_client_fd(pid_t pid, int fd, VInputDevice dev);
    bool is_virtual_input_fd(pid_t pid, int fd) const;
    void on_process_exit(pid_t pid);

    // Emulates EVIOCGVERSION, EVIOCGID, EVIOCGNAME, EVIOCGBIT, EVIOCGABS, EVIOCGPROP.
    // Returns >= 0 on success (bytes written or 0), or -errno.
    int64_t handle_ioctl(pid_t pid, int fd, unsigned long cmd, uint64_t arg_ptr) const;

    static bool device_from_guest_path(std::string_view guest_path, VInputDevice& out_dev);

    const std::string& input_socket_path() const noexcept { return sock_path_; }

private:
    void bridge_loop();
    void emit_to_fifo(VInputDevice dev, const struct input_event& ev);

    std::string rootfs_root_;
    std::string sock_path_;
    std::string fifo_paths_[2];
    int fifo_wr_fds_[2] = {-1, -1};
    int sock_fd_ = -1;
    uint32_t screen_w_ = 1400;
    uint32_t screen_h_ = 876;
    InputMemOps mem_ops_;

    std::unordered_map<uint64_t, VInputDevice> fd_map_;
    std::atomic<bool> running_{false};
    std::thread bridge_thread_;
};

}  // namespace vguest
