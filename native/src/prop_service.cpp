#include "prop_service.hpp"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <linux/futex.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>
#include <vector>

namespace vguest {

namespace {

// Exact Android 12 Bionic prop_area ABI constants (ContextsPreSplit single-file mode)
constexpr uint32_t kPropAreaMagic = 0x504f5250U;   // "PROP"
constexpr uint32_t kPropAreaVersion = 0xfc6ed0abU; // Android 5+ / 12
constexpr size_t kPropAreaSize = 128 * 1024;       // Exact Bionic PA_SIZE (128 KiB)
constexpr size_t kPropAreaHeaderSize = 128;
constexpr size_t kPropValueMax = 92;               // 91 chars + NUL
constexpr uint32_t kLongFlag = 1u << 16;
constexpr uint32_t kLongLegacyErrorOffset = 56;

// Android property_service socket protocol commands
constexpr uint32_t kPropMsgSetProp = 1;
constexpr uint32_t kPropMsgSetProp2 = 0x00020001U;
constexpr uint32_t kPropSuccess = 0;
constexpr uint32_t kPropErrorInvalidArg = 0x0001;

// Bionic prop_area header (128 bytes)
struct PropAreaHeader {
    uint32_t bytes_used;
    std::atomic<uint32_t> serial;
    uint32_t magic;
    uint32_t version;
    uint32_t reserved[28];
};
static_assert(sizeof(PropAreaHeader) == kPropAreaHeaderSize, "PropAreaHeader must be 128 bytes");

// Bionic prop_bt trie node (20 bytes + NUL-terminated segment name)
struct PropBt {
    uint32_t namelen;
    std::atomic<uint32_t> prop;
    std::atomic<uint32_t> left;
    std::atomic<uint32_t> right;
    std::atomic<uint32_t> children;
    char* name_ptr() noexcept { return reinterpret_cast<char*>(this + 1); }
    const char* name_ptr() const noexcept { return reinterpret_cast<const char*>(this + 1); }
};
static_assert(sizeof(PropBt) == 20, "PropBt header must be 20 bytes");

// Bionic prop_info entry (96 bytes + NUL-terminated full property name)
struct PropInfo {
    std::atomic<uint32_t> serial;
    char value[kPropValueMax];
    char* name_ptr() noexcept { return reinterpret_cast<char*>(this + 1); }
};
static_assert(sizeof(PropInfo) == 96, "PropInfo header must be 96 bytes");

uint32_t align4(uint32_t n) { return (n + 3u) & ~3u; }

int cmp_prop_name(std::string_view a, const char* b, uint32_t b_len) {
    if (a.size() < b_len) return -1;
    if (a.size() > b_len) return 1;
    return std::memcmp(a.data(), b, b_len);
}

bool read_exact(int fd, void* buf, size_t len) {
    auto* p = reinterpret_cast<uint8_t*>(buf);
    size_t got = 0;
    while (got < len) {
        ssize_t n = ::read(fd, p + got, len - got);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            return false;
        }
        got += static_cast<size_t>(n);
    }
    return true;
}

void mkdir_p(const std::string& dir) {
    std::string cur;
    for (size_t i = 0; i < dir.size(); ++i) {
        cur.push_back(dir[i]);
        if (dir[i] == '/' && cur.size() > 1) {
            ::mkdir(cur.c_str(), 0755);
        }
    }
    ::mkdir(cur.c_str(), 0755);
}

void remove_dir_if_exists(const std::string& path) {
    struct stat st {};
    if (::lstat(path.c_str(), &st) != 0) return;
    if (!S_ISDIR(st.st_mode)) {
        ::unlink(path.c_str());
        return;
    }
    DIR* d = ::opendir(path.c_str());
    if (d) {
        while (struct dirent* ent = ::readdir(d)) {
            if (std::strcmp(ent->d_name, ".") == 0 || std::strcmp(ent->d_name, "..") == 0) {
                continue;
            }
            remove_dir_if_exists(path + "/" + ent->d_name);
        }
        ::closedir(d);
    }
    ::rmdir(path.c_str());
}

}  // namespace

PropertyService::PropertyService(std::string rootfs_root)
    : rootfs_root_(std::move(rootfs_root)) {
    if (rootfs_root_.size() > 1 && rootfs_root_.back() == '/') {
        rootfs_root_.pop_back();
    }
    // Bionic ContextsPreSplit mode: /dev/__properties__ is a single 128 KiB prop_area file.
    // This bypasses SELinux property_info/property_contexts parsing and works across all AOSP versions.
    props_dir_ = rootfs_root_ + "/dev";
    property_info_path_ = rootfs_root_ + "/dev/__properties__";
    serial_area_path_ = rootfs_root_ + "/dev/__properties__";
    default_area_path_ = rootfs_root_ + "/dev/__properties__";
    socket_path_ = rootfs_root_ + "/dev/socket/property_service";
}

PropertyService::~PropertyService() {
    stop();
}

bool PropertyService::init_property_info_file() {
    // Unused in ContextsPreSplit single-file mode.
    return true;
}

bool PropertyService::init_prop_area_file(const std::string& path,
                                          uint8_t*& out_map,
                                          size_t& out_size) {
    // Remove legacy /dev/__properties__ directory if created by an earlier run
    remove_dir_if_exists(path);

    int fd = ::open(path.c_str(), O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0) return false;
    if (::ftruncate(fd, static_cast<off_t>(kPropAreaSize)) != 0) {
        ::close(fd);
        return false;
    }

    void* map = ::mmap(nullptr, kPropAreaSize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    ::close(fd);
    if (map == MAP_FAILED) return false;

    std::memset(map, 0, kPropAreaSize);
    auto* hdr = reinterpret_cast<PropAreaHeader*>(map);
    hdr->magic = kPropAreaMagic;
    hdr->version = kPropAreaVersion;
    hdr->serial.store(0, std::memory_order_relaxed);
    hdr->bytes_used = align4(sizeof(PropBt) + 1);

    out_map = reinterpret_cast<uint8_t*>(map);
    out_size = kPropAreaSize;
    return true;
}

uint32_t PropertyService::alloc_area_bytes(uint32_t bytes) {
    auto* hdr = reinterpret_cast<PropAreaHeader*>(area_map_);
    uint32_t aligned = align4(bytes);
    if (kPropAreaHeaderSize + hdr->bytes_used + aligned > area_map_size_) {
        return 0;
    }
    uint32_t off = hdr->bytes_used;
    hdr->bytes_used += aligned;
    return off;
}

void PropertyService::bump_serial_and_wake(uint32_t* serial_ptr) {
    auto* atom = reinterpret_cast<std::atomic<uint32_t>*>(serial_ptr);
    atom->fetch_add(1, std::memory_order_release);
    ::syscall(SYS_futex, serial_ptr, FUTEX_WAKE, INT32_MAX, nullptr, nullptr, 0);
}

bool PropertyService::write_prop_info_value(uint32_t prop_off,
                                            std::string_view name,
                                            std::string_view value) {
    uint8_t* data = area_map_ + kPropAreaHeaderSize;
    auto* pi = reinterpret_cast<PropInfo*>(data + prop_off);

    uint32_t old_serial = pi->serial.load(std::memory_order_relaxed);
    uint32_t dirty_serial = (old_serial & 0x0000FFFFu) | 1u;
    pi->serial.store(dirty_serial, std::memory_order_release);

    if (value.size() < kPropValueMax) {
        std::memset(pi->value, 0, kPropValueMax);
        std::memcpy(pi->value, value.data(), value.size());
        pi->value[value.size()] = '\0';

        uint32_t next_counter = ((old_serial & 0x0000FFFEu) + 2u) & 0x0000FFFEu;
        uint32_t final_serial = (static_cast<uint32_t>(value.size()) << 24) | next_counter;
        pi->serial.store(final_serial, std::memory_order_release);
    } else {
        uint32_t long_off = alloc_area_bytes(static_cast<uint32_t>(value.size() + 1));
        if (long_off == 0) return false;
        std::memcpy(data + long_off, value.data(), value.size());
        data[long_off + value.size()] = '\0';

        std::memset(pi->value, 0, kPropValueMax);
        std::snprintf(pi->value, kLongLegacyErrorOffset, "long_prop");
        uint32_t rel_off = long_off - prop_off;
        std::memcpy(pi->value + kLongLegacyErrorOffset, &rel_off, sizeof(uint32_t));

        uint32_t next_counter = ((old_serial & 0x0000FFFEu) + 2u) & 0x0000FFFEu;
        uint32_t final_serial = kLongFlag | next_counter;
        pi->serial.store(final_serial, std::memory_order_release);
    }

    (void)name;
    ::syscall(SYS_futex, &pi->serial, FUTEX_WAKE, INT32_MAX, nullptr, nullptr, 0);

    auto* area_hdr = reinterpret_cast<PropAreaHeader*>(area_map_);
    bump_serial_and_wake(reinterpret_cast<uint32_t*>(&area_hdr->serial));
    return true;
}

uint32_t PropertyService::find_or_create_prop_info(std::string_view name,
                                                   std::string_view value,
                                                   bool create) {
    if (!area_map_ || name.empty()) return 0;
    uint8_t* data = area_map_ + kPropAreaHeaderSize;
    uint32_t current_bt_off = 0;

    size_t pos = 0;
    while (pos < name.size()) {
        size_t dot = name.find('.', pos);
        std::string_view seg = (dot == std::string_view::npos)
                                   ? name.substr(pos)
                                   : name.substr(pos, dot - pos);
        pos = (dot == std::string_view::npos) ? name.size() : (dot + 1);

        auto* parent_bt = reinterpret_cast<PropBt*>(data + current_bt_off);
        uint32_t child_off = parent_bt->children.load(std::memory_order_acquire);

        if (child_off == 0) {
            if (!create) return 0;
            uint32_t new_bt_off = alloc_area_bytes(
                static_cast<uint32_t>(sizeof(PropBt) + seg.size() + 1));
            if (new_bt_off == 0) return 0;
            auto* nbt = reinterpret_cast<PropBt*>(data + new_bt_off);
            nbt->namelen = static_cast<uint32_t>(seg.size());
            std::memcpy(nbt->name_ptr(), seg.data(), seg.size());
            nbt->name_ptr()[seg.size()] = '\0';
            parent_bt->children.store(new_bt_off, std::memory_order_release);
            current_bt_off = new_bt_off;
            continue;
        }

        uint32_t cur = child_off;
        while (true) {
            auto* bt = reinterpret_cast<PropBt*>(data + cur);
            int cmp = cmp_prop_name(seg, bt->name_ptr(), bt->namelen);
            if (cmp == 0) {
                current_bt_off = cur;
                break;
            }
            std::atomic<uint32_t>& branch = (cmp < 0) ? bt->left : bt->right;
            uint32_t next = branch.load(std::memory_order_acquire);
            if (next != 0) {
                cur = next;
                continue;
            }
            if (!create) return 0;
            uint32_t new_bt_off = alloc_area_bytes(
                static_cast<uint32_t>(sizeof(PropBt) + seg.size() + 1));
            if (new_bt_off == 0) return 0;
            auto* nbt = reinterpret_cast<PropBt*>(data + new_bt_off);
            nbt->namelen = static_cast<uint32_t>(seg.size());
            std::memcpy(nbt->name_ptr(), seg.data(), seg.size());
            nbt->name_ptr()[seg.size()] = '\0';
            branch.store(new_bt_off, std::memory_order_release);
            current_bt_off = new_bt_off;
            break;
        }
    }

    auto* leaf = reinterpret_cast<PropBt*>(data + current_bt_off);
    uint32_t prop_off = leaf->prop.load(std::memory_order_acquire);
    if (prop_off == 0) {
        if (!create) return 0;
        prop_off = alloc_area_bytes(static_cast<uint32_t>(sizeof(PropInfo) + name.size() + 1));
        if (prop_off == 0) return 0;
        auto* pi = reinterpret_cast<PropInfo*>(data + prop_off);
        std::memcpy(pi->name_ptr(), name.data(), name.size());
        pi->name_ptr()[name.size()] = '\0';
        write_prop_info_value(prop_off, name, value);
        leaf->prop.store(prop_off, std::memory_order_release);
        return prop_off;
    }

    if (create) {
        write_prop_info_value(prop_off, name, value);
    }
    return prop_off;
}

bool PropertyService::set(std::string_view name, std::string_view value) {
    if (name.empty()) return false;
    std::lock_guard<std::mutex> lk(area_mu_);
    return find_or_create_prop_info(name, value, true) != 0;
}

bool PropertyService::get(std::string_view name, std::string& out_value) const {
    if (name.empty() || !area_map_) return false;
    std::lock_guard<std::mutex> lk(area_mu_);
    uint32_t prop_off = const_cast<PropertyService*>(this)->find_or_create_prop_info(name, "", false);
    if (prop_off == 0) return false;

    const uint8_t* data = area_map_ + kPropAreaHeaderSize;
    const auto* pi = reinterpret_cast<const PropInfo*>(data + prop_off);
    uint32_t ser = pi->serial.load(std::memory_order_acquire);
    if (ser & kLongFlag) {
        uint32_t rel_off = 0;
        std::memcpy(&rel_off, pi->value + kLongLegacyErrorOffset, sizeof(uint32_t));
        out_value = reinterpret_cast<const char*>(data + prop_off + rel_off);
    } else {
        uint32_t len = ser >> 24;
        if (len >= kPropValueMax) len = kPropValueMax - 1;
        out_value.assign(pi->value, len);
    }
    return true;
}

uint32_t PropertyService::global_serial() const noexcept {
    if (!area_map_) return 0;
    const auto* hdr = reinterpret_cast<const PropAreaHeader*>(area_map_);
    return hdr->serial.load(std::memory_order_acquire);
}

void PropertyService::load_build_prop_file(const std::string& path) {
    std::ifstream in(path);
    if (!in.is_open()) return;
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty() || line[0] == '#') continue;
        size_t eq = line.find('=');
        if (eq == std::string::npos || eq == 0) continue;
        std::string k = line.substr(0, eq);
        std::string v = line.substr(eq + 1);
        while (!v.empty() && (v.back() == '\r' || v.back() == '\n')) v.pop_back();
        set(k, v);
    }
}

void PropertyService::seed_default_aosp12_properties() {
    load_build_prop_file(rootfs_root_ + "/system/build.prop");

    const std::pair<const char*, const char*> defaults[] = {
        {"ro.property_service.version", "2"},
        {"ro.build.version.sdk", "31"},
        {"ro.build.version.release", "12"},
        {"ro.product.cpu.abi", "arm64-v8a"},
        {"ro.product.cpu.abilist", "arm64-v8a"},
        {"ro.product.cpu.abilist64", "arm64-v8a"},
        {"ro.zygote", "zygote64"},
        {"ro.boot.hardware", "virt"},
        {"ro.hardware", "virt"},
        {"ro.hardware.gralloc", "virt"},
        {"ro.hardware.hwcomposer", "virt"},
        {"ro.hardware.egl", "swiftshader"},
        {"debug.renderengine.backend", "gles"},
        {"ro.surface_flinger.use_color_management", "false"},
        {"ro.opengles.version", "196608"},
        {"ro.sf.lcd_density", "280"},
        {"ro.zygote.disable_gl_preload", "true"},
        {"config.disable_bluetooth", "true"},
        {"config.disable_telephony", "true"},
        {"config.disable_cameraservice", "true"},
        {"config.disable_consumerir", "true"},
        {"persist.sys.dalvik.vm.lib.2", "libart.so"},
        {"ro.dalvik.vm.native.bridge", "0"},
        {"dalvik.vm.isa.arm64.variant", "kryo"},
        {"dalvik.vm.isa.arm64.features", "default"},
        {"dalvik.vm.usejit", "true"},
        {"dalvik.vm.extra-opts", "-Xnoimage-dex2oat"},
        {"dalvik.vm.boot-dex2oat-threads", "4"},
        {"dalvik.vm.heapstartsize", "16m"},
        {"dalvik.vm.heapgrowthlimit", "256m"},
        {"dalvik.vm.heapsize", "512m"},
        {"dalvik.vm.heaptargetutilization", "0.75"},
        {"dalvik.vm.heapminfree", "2m"},
        {"dalvik.vm.heapmaxfree", "8m"},
        {"ro.apex.updatable", "false"},
        {"ro.crypto.state", "unencrypted"},
        {"ro.debuggable", "1"},
        {"ro.secure", "0"},
        {"debug.sf.nobootanimation", "1"},
        {"ro.surface_flinger.use_color_management", "false"},
        {"sys.boot_completed", "0"},
    };
    for (const auto& [k, v] : defaults) {
        set(k, v);
    }
}

bool PropertyService::start() {
    if (running_.load()) return true;

    mkdir_p(props_dir_);
    mkdir_p(rootfs_root_ + "/dev/socket");

    if (!init_prop_area_file(default_area_path_, area_map_, area_map_size_)) return false;
    serial_map_ = area_map_;
    serial_map_size_ = area_map_size_;

    seed_default_aosp12_properties();

    ::unlink(socket_path_.c_str());
    listen_fd_ = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (listen_fd_ < 0) return false;

    struct sockaddr_un addr {};
    addr.sun_family = AF_UNIX;
    if (socket_path_.size() >= sizeof(addr.sun_path)) {
        ::close(listen_fd_);
        listen_fd_ = -1;
        return false;
    }
    std::strncpy(addr.sun_path, socket_path_.c_str(), sizeof(addr.sun_path) - 1);

    if (::bind(listen_fd_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) != 0 ||
        ::listen(listen_fd_, 32) != 0) {
        ::close(listen_fd_);
        listen_fd_ = -1;
        return false;
    }
    ::chmod(socket_path_.c_str(), 0666);

    running_.store(true);
    server_thread_ = std::thread(&PropertyService::server_loop, this);
    return true;
}

void PropertyService::stop() {
    if (running_.exchange(false)) {
        if (server_thread_.joinable()) {
            server_thread_.join();
        }
    }
    if (listen_fd_ >= 0) {
        ::close(listen_fd_);
        listen_fd_ = -1;
    }
    ::unlink(socket_path_.c_str());
    if (area_map_) {
        ::munmap(area_map_, area_map_size_);
        area_map_ = nullptr;
        serial_map_ = nullptr;
    }
}

void PropertyService::server_loop() {
    while (running_.load()) {
        struct pollfd pfd { listen_fd_, POLLIN, 0 };
        int rc = ::poll(&pfd, 1, 100);
        if (rc <= 0) continue;
        if (pfd.revents & POLLIN) {
            int cfd = ::accept4(listen_fd_, nullptr, nullptr, SOCK_CLOEXEC);
            if (cfd >= 0) {
                handle_client(cfd);
                ::close(cfd);
            }
        }
    }
}

void PropertyService::handle_client(int client_fd) {
    uint32_t cmd = 0;
    if (!read_exact(client_fd, &cmd, sizeof(cmd))) return;

    uint32_t status = kPropErrorInvalidArg;
    if (cmd == kPropMsgSetProp2) {
        uint32_t name_len = 0;
        if (!read_exact(client_fd, &name_len, sizeof(name_len)) || name_len == 0 || name_len > 256) {
            ::write(client_fd, &status, sizeof(status));
            return;
        }
        std::string name(name_len, '\0');
        if (!read_exact(client_fd, name.data(), name_len)) return;

        uint32_t val_len = 0;
        if (!read_exact(client_fd, &val_len, sizeof(val_len)) || val_len > 4096) {
            ::write(client_fd, &status, sizeof(status));
            return;
        }
        std::string val(val_len, '\0');
        if (val_len > 0 && !read_exact(client_fd, val.data(), val_len)) return;

        status = set(name, val) ? kPropSuccess : kPropErrorInvalidArg;
        ::write(client_fd, &status, sizeof(status));
    } else if (cmd == kPropMsgSetProp) {
        char name_buf[32] = {};
        char val_buf[kPropValueMax] = {};
        if (!read_exact(client_fd, name_buf, sizeof(name_buf))) return;
        if (!read_exact(client_fd, val_buf, sizeof(val_buf))) return;
        name_buf[31] = '\0';
        val_buf[kPropValueMax - 1] = '\0';
        status = set(name_buf, val_buf) ? kPropSuccess : kPropErrorInvalidArg;
        ::write(client_fd, &status, sizeof(status));
    }
}

}  // namespace vguest
