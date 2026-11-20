#pragma once

#include <atomic>
#include <string>
#include <thread>

namespace vguest {

// Lightweight mock /dev/socket/logdw receiver that prints guest Android ALOG*
// messages (zygote64, libart, SurfaceFlinger, system_server) live to stderr.
class LogdSink {
public:
    explicit LogdSink(std::string rootfs_root);
    ~LogdSink();

    LogdSink(const LogdSink&) = delete;
    LogdSink& operator=(const LogdSink&) = delete;

    bool start();
    void stop();

    const std::string& socket_path() const noexcept { return sock_path_; }

private:
    void loop();

    std::string rootfs_root_;
    std::string sock_path_;
    int sock_fd_ = -1;
    std::atomic<bool> running_{false};
    std::thread thread_;
};

}  // namespace vguest
