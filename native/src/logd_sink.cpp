#include "logd_sink.hpp"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

namespace vguest {

namespace {

// Android liblog /dev/socket/logdw datagram header (11 bytes):
//   uint8_t  id;      // log buffer id (0=main, 1=radio, 2=events, 3=system, 4=crash)
//   uint16_t tid;
//   uint32_t tv_sec;
//   uint32_t tv_nsec;
// Followed by: [uint8_t priority][tag\0][message\0]
constexpr size_t kLogdwHeaderSize = 11;

char prio_char(uint8_t p) {
    switch (p) {
        case 2: return 'V';
        case 3: return 'D';
        case 4: return 'I';
        case 5: return 'W';
        case 6: return 'E';
        case 7: return 'F';
        default: return '?';
    }
}

}  // namespace

LogdSink::LogdSink(std::string rootfs_root) : rootfs_root_(std::move(rootfs_root)) {
    if (rootfs_root_.size() > 1 && rootfs_root_.back() == '/') {
        rootfs_root_.pop_back();
    }
    sock_path_ = rootfs_root_ + "/dev/socket/logdw";
}

LogdSink::~LogdSink() {
    stop();
}

bool LogdSink::start() {
    if (running_.load()) return true;
    ::mkdir((rootfs_root_ + "/dev").c_str(), 0755);
    ::mkdir((rootfs_root_ + "/dev/socket").c_str(), 0755);

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
    thread_ = std::thread(&LogdSink::loop, this);
    return true;
}

void LogdSink::stop() {
    if (running_.exchange(false)) {
        if (thread_.joinable()) thread_.join();
    }
    if (sock_fd_ >= 0) {
        ::close(sock_fd_);
        sock_fd_ = -1;
    }
    ::unlink(sock_path_.c_str());
}

void LogdSink::loop() {
    uint8_t buf[4096];
    while (running_.load()) {
        struct pollfd pfd { sock_fd_, POLLIN, 0 };
        if (::poll(&pfd, 1, 50) <= 0) continue;
        if (pfd.revents & POLLIN) {
            while (true) {
                ssize_t n = ::recv(sock_fd_, buf, sizeof(buf) - 1, 0);
                if (n <= static_cast<ssize_t>(kLogdwHeaderSize + 2)) break;
                buf[n] = '\0';

                uint8_t log_id = buf[0];
                if (log_id == 2) continue;  // skip binary event log buffer

                uint8_t prio = buf[kLogdwHeaderSize];
                if (prio < 4) continue;  // stream I, W, E, F to keep console readable

                const char* tag = reinterpret_cast<const char*>(buf + kLogdwHeaderSize + 1);
                size_t tag_len = ::strnlen(tag, static_cast<size_t>(n) - kLogdwHeaderSize - 1);
                const char* msg = "";
                if (kLogdwHeaderSize + 1 + tag_len + 1 < static_cast<size_t>(n)) {
                    msg = tag + tag_len + 1;
                }
                std::fprintf(stderr, "[logd/%c] %s: %s\n", prio_char(prio), tag, msg);
                std::fflush(stderr);
            }
        }
    }
}

}  // namespace vguest
