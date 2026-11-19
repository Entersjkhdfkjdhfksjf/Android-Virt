#pragma once

#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>

namespace vguest {

// Native Bionic-compatible Android 12 property area & /dev/socket/property_service daemon.
// Produces:
//   <rootfs>/dev/__properties__/property_info             (serialized prefix trie)
//   <rootfs>/dev/__properties__/properties_serial         (global serial prop_area)
//   <rootfs>/dev/__properties__/u:object_r:default_prop:s0 (unified shared prop_area)
//   <rootfs>/dev/socket/property_service                  (AF_UNIX SOCK_STREAM server)
class PropertyService {
public:
    explicit PropertyService(std::string rootfs_root);
    ~PropertyService();

    PropertyService(const PropertyService&) = delete;
    PropertyService& operator=(const PropertyService&) = delete;

    // Initializes /dev/__properties__ files, seeds mandatory AOSP 12 properties
    // (plus optional <rootfs>/system/build.prop), and starts the socket listener thread.
    bool start();

    // Stops the listener thread and unmaps shared property areas.
    void stop();

    // Sets or updates a property in the shared prop_area and wakes futex waiters.
    bool set(std::string_view name, std::string_view value);

    // Reads a property directly from the Bionic prop_area binary trie (also used in tests).
    bool get(std::string_view name, std::string& out_value) const;

    // Returns current global property serial counter.
    uint32_t global_serial() const noexcept;

    // Path to the host UNIX socket (<rootfs>/dev/socket/property_service).
    const std::string& socket_path() const noexcept { return socket_path_; }

    // Path to the unified prop_area file.
    const std::string& default_area_path() const noexcept { return default_area_path_; }

    // Path to the serialized property_info file.
    const std::string& property_info_path() const noexcept { return property_info_path_; }

private:
    bool init_property_info_file();
    bool init_prop_area_file(const std::string& path, uint8_t*& out_map, size_t& out_size);
    void seed_default_aosp12_properties();
    void load_build_prop_file(const std::string& path);

    // Low-level Bionic prop_area trie operations (caller holds area_mu_).
    uint32_t alloc_area_bytes(uint32_t bytes);
    uint32_t find_or_create_prop_info(std::string_view name, std::string_view value, bool create);
    bool write_prop_info_value(uint32_t prop_off, std::string_view name, std::string_view value);
    void bump_serial_and_wake(uint32_t* serial_ptr);

    void server_loop();
    void handle_client(int client_fd);

    std::string rootfs_root_;
    std::string props_dir_;
    std::string property_info_path_;
    std::string serial_area_path_;
    std::string default_area_path_;
    std::string socket_path_;

    uint8_t* serial_map_ = nullptr;
    size_t serial_map_size_ = 0;
    uint8_t* area_map_ = nullptr;
    size_t area_map_size_ = 0;

    mutable std::mutex area_mu_;
    int listen_fd_ = -1;
    std::atomic<bool> running_{false};
    std::thread server_thread_;
};

}  // namespace vguest
