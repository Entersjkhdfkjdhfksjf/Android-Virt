#include "vinput.hpp"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>
#include <vector>

namespace vguest {

namespace {

uint64_t fd_key(pid_t pid, int fd) {
    return (static_cast<uint64_t>(static_cast<uint32_t>(pid)) << 32) |
           static_cast<uint32_t>(fd);
}

void set_bit(std::vector<uint8_t>& bits, unsigned int bit) {
    size_t byte_idx = bit / 8;
    if (byte_idx < bits.size()) {
        bits[byte_idx] |= static_cast<uint8_t>(1u << (bit % 8));
    }
}

}  // namespace

VInputHub::VInputHub(std::string rootfs_root, uint32_t screen_w, uint32_t screen_h,
                     InputMemOps mem_ops)
    : rootfs_root_(std::move(rootfs_root)),
      screen_w_(screen_w),
      screen_h_(screen_h),
      mem_ops_(std::move(mem_ops)) {
    if (rootfs_root_.size() > 1 && rootfs_root_.back() == '/') {
        rootfs_root_.pop_back();
    }
    sock_path_ = rootfs_root_ + "/dev/socket/vguest_input";
    fifo_paths_[0] = rootfs_root_ + "/tmp/.vevdev_touch0";
    fifo_paths_[1] = rootfs_root_ + "/tmp/.vevdev_spen1";
}

VInputHub::~VInputHub() {
    stop();
}

bool VInputHub::device_from_guest_path(std::string_view guest_path, VInputDevice& out_dev) {
    if (guest_path == "/dev/input/event0") {
        out_dev = VInputDevice::kTouchscreen;
        return true;
    }
    if (guest_path == "/dev/input/event1") {
        out_dev = VInputDevice::kStylus;
        return true;
    }
    return false;
}

bool VInputHub::start() {
    if (running_.load()) return true;

    ::mkdir((rootfs_root_ + "/tmp").c_str(), 0755);
    ::mkdir((rootfs_root_ + "/dev").c_str(), 0755);
    ::mkdir((rootfs_root_ + "/dev/socket").c_str(), 0755);

    // Create named FIFOs for /dev/input/event0 and event1; open O_RDWR|O_NONBLOCK so writers never block
    for (int i = 0; i < 2; ++i) {
        ::unlink(fifo_paths_[i].c_str());
        if (::mkfifo(fifo_paths_[i].c_str(), 0666) != 0 && errno != EEXIST) {
            return false;
        }
        fifo_wr_fds_[i] = ::open(fifo_paths_[i].c_str(), O_RDWR | O_NONBLOCK | O_CLOEXEC);
    }

    ::unlink(sock_path_.c_str());
    sock_fd_ = ::socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (sock_fd_ < 0) return false;

    struct sockaddr_un addr {};
    addr.sun_family = AF_UNIX;
    if (sock_path_.size() >= sizeof(addr.sun_path)) {
        ::close(sock_fd_);
        sock_fd_ = -1;
        return false;
    }
    std::strncpy(addr.sun_path, sock_path_.c_str(), sizeof(addr.sun_path) - 1);
    if (::bind(sock_fd_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) != 0) {
        ::close(sock_fd_);
        sock_fd_ = -1;
        return false;
    }
    ::chmod(sock_path_.c_str(), 0666);

    running_.store(true);
    bridge_thread_ = std::thread(&VInputHub::bridge_loop, this);
    return true;
}

void VInputHub::stop() {
    if (running_.exchange(false)) {
        if (bridge_thread_.joinable()) bridge_thread_.join();
    }
    if (sock_fd_ >= 0) {
        ::close(sock_fd_);
        sock_fd_ = -1;
    }
    ::unlink(sock_path_.c_str());
    for (int i = 0; i < 2; ++i) {
        if (fifo_wr_fds_[i] >= 0) {
            ::close(fifo_wr_fds_[i]);
            fifo_wr_fds_[i] = -1;
        }
        ::unlink(fifo_paths_[i].c_str());
    }
}

std::string VInputHub::prepare_open_path(VInputDevice dev) const {
    return fifo_paths_[static_cast<size_t>(dev)];
}

void VInputHub::register_client_fd(pid_t pid, int fd, VInputDevice dev) {
    fd_map_[fd_key(pid, fd)] = dev;
}

bool VInputHub::is_virtual_input_fd(pid_t pid, int fd) const {
    return fd_map_.find(fd_key(pid, fd)) != fd_map_.end();
}

void VInputHub::on_process_exit(pid_t pid) {
    for (auto it = fd_map_.begin(); it != fd_map_.end(); ) {
        if (static_cast<pid_t>(it->first >> 32) == pid) it = fd_map_.erase(it);
        else ++it;
    }
}

void VInputHub::emit_to_fifo(VInputDevice dev, const struct input_event& ev) {
    int fd = fifo_wr_fds_[static_cast<size_t>(dev)];
    if (fd >= 0) {
        (void)::write(fd, &ev, sizeof(ev));
    }
}

void VInputHub::bridge_loop() {
    while (running_.load()) {
        struct pollfd pfd { sock_fd_, POLLIN, 0 };
        if (::poll(&pfd, 1, 50) <= 0) continue;
        if (pfd.revents & POLLIN) {
            HostInputPacket pkt {};
            while (::recv(sock_fd_, &pkt, sizeof(pkt), 0) == static_cast<ssize_t>(sizeof(pkt))) {
                struct input_event ev {};
                struct timeval tv {};
                ::gettimeofday(&tv, nullptr);
                ev.time = tv;
                ev.type = pkt.type;
                ev.code = pkt.code;
                ev.value = pkt.value;
                VInputDevice dev = (pkt.dev_idx == 1) ? VInputDevice::kStylus
                                                      : VInputDevice::kTouchscreen;
                emit_to_fifo(dev, ev);
            }
        }
    }
}

int64_t VInputHub::handle_ioctl(pid_t pid, int fd, unsigned long cmd, uint64_t arg_ptr) const {
    auto it = fd_map_.find(fd_key(pid, fd));
    if (it == fd_map_.end()) return -ENOTTY;
    const VInputDevice dev = it->second;

    const unsigned int nr = _IOC_NR(cmd);
    const unsigned int size = _IOC_SIZE(cmd);

    // EVIOCGVERSION (0x01)
    if (nr == 0x01) {
        int ver = EV_VERSION;
        return mem_ops_.write(pid, arg_ptr, &ver, sizeof(ver)) ? 0 : -EFAULT;
    }

    // EVIOCGID (0x02)
    if (nr == 0x02) {
        struct input_id id {};
        id.bustype = BUS_VIRTUAL;
        id.vendor = 0x18D1;
        id.product = (dev == VInputDevice::kStylus) ? 0x5002 : 0x5001;
        id.version = 0x0100;
        return mem_ops_.write(pid, arg_ptr, &id, sizeof(id)) ? 0 : -EFAULT;
    }

    // EVIOCGNAME (0x06)
    if (nr == 0x06) {
        const char* name = (dev == VInputDevice::kStylus)
                               ? "vguest_spen_digitizer"
                               : "vguest_multitouch_screen";
        size_t len = std::min<size_t>(std::strlen(name) + 1, size);
        return mem_ops_.write(pid, arg_ptr, name, len) ? static_cast<int64_t>(len) : -EFAULT;
    }

    // EVIOCGPROP (0x09)
    if (nr == 0x09) {
        std::vector<uint8_t> bits(size, 0);
        set_bit(bits, INPUT_PROP_DIRECT);
        return mem_ops_.write(pid, arg_ptr, bits.data(), bits.size())
                   ? static_cast<int64_t>(bits.size()) : -EFAULT;
    }

    // EVIOCGBIT(ev, len): nr = 0x20 + ev
    if (nr >= 0x20 && nr < 0x40) {
        unsigned int ev_type = nr - 0x20;
        std::vector<uint8_t> bits(size, 0);
        if (ev_type == 0) {
            set_bit(bits, EV_SYN);
            set_bit(bits, EV_KEY);
            set_bit(bits, EV_ABS);
        } else if (ev_type == EV_KEY) {
            set_bit(bits, BTN_TOUCH);
            if (dev == VInputDevice::kStylus) {
                set_bit(bits, BTN_TOOL_PEN);
                set_bit(bits, BTN_STYLUS);
                set_bit(bits, BTN_STYLUS2);
            }
        } else if (ev_type == EV_ABS) {
            if (dev == VInputDevice::kTouchscreen) {
                set_bit(bits, ABS_MT_SLOT);
                set_bit(bits, ABS_MT_TRACKING_ID);
                set_bit(bits, ABS_MT_POSITION_X);
                set_bit(bits, ABS_MT_POSITION_Y);
                set_bit(bits, ABS_MT_TOUCH_MAJOR);
                set_bit(bits, ABS_MT_PRESSURE);
            } else {
                set_bit(bits, ABS_X);
                set_bit(bits, ABS_Y);
                set_bit(bits, ABS_PRESSURE);
                set_bit(bits, ABS_TILT_X);
                set_bit(bits, ABS_TILT_Y);
                set_bit(bits, ABS_DISTANCE);
            }
        }
        return mem_ops_.write(pid, arg_ptr, bits.data(), bits.size())
                   ? static_cast<int64_t>(bits.size()) : -EFAULT;
    }

    // EVIOCGABS(abs): nr = 0x40 + abs
    if (nr >= 0x40 && nr < 0x80) {
        unsigned int abs_code = nr - 0x40;
        struct input_absinfo info {};
        if (abs_code == ABS_X || abs_code == ABS_MT_POSITION_X) {
            info.minimum = 0;
            info.maximum = static_cast<int32_t>(screen_w_ - 1);
        } else if (abs_code == ABS_Y || abs_code == ABS_MT_POSITION_Y) {
            info.minimum = 0;
            info.maximum = static_cast<int32_t>(screen_h_ - 1);
        } else if (abs_code == ABS_MT_SLOT) {
            info.minimum = 0;
            info.maximum = 9;
        } else if (abs_code == ABS_MT_TRACKING_ID) {
            info.minimum = 0;
            info.maximum = 65535;
        } else if (abs_code == ABS_PRESSURE || abs_code == ABS_MT_PRESSURE) {
            info.minimum = 0;
            info.maximum = 4096;  // S Pen 4096 pressure levels
        } else if (abs_code == ABS_TILT_X || abs_code == ABS_TILT_Y) {
            info.minimum = -60;
            info.maximum = 60;
        } else if (abs_code == ABS_DISTANCE) {
            info.minimum = 0;
            info.maximum = 255;
        }
        return mem_ops_.write(pid, arg_ptr, &info, sizeof(info)) ? 0 : -EFAULT;
    }

    return 0;
}

}  // namespace vguest
