/*
 * VGuest Virtual HWC2 HAL (hwcomposer.virt.so / hwcomposer.default.so)
 *
 * Implements AOSP 12 HWC2 (hwc2_device_t) with:
 * - Single primary physical display (1400x876 @ 60 Hz, 280 DPI)
 * - Software 60 Hz VSync thread
 * - Forces all layers to HWC2_COMPOSITION_CLIENT (composited by SwiftShader RenderEngine)
 * - Copies presented client target buffers (allocated by vguest_gralloc.c) directly into
 *   the Phase 5 triple-buffered shared-memory ring (/tmp/.vguest_fb_ring).
 */

#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <hardware/hardware.h>
#include <hardware/hwcomposer2.h>
#include <mutex>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <unordered_map>
#include <vector>

#include "virt_fb_protocol.hpp"

namespace {

constexpr uint32_t kDefaultWidth = 1400;
constexpr uint32_t kDefaultHeight = 876;
constexpr int32_t kVsyncPeriodNs = 16666666;  // 60 Hz
constexpr int32_t kDpiScaled = 280000;        // 280 DPI * 1000
constexpr hwc2_display_t kPrimaryDisplayId = 0;
constexpr hwc2_config_t kPrimaryConfigId = 0;

// Must match vguest_gralloc.c
constexpr int kVguestGrallocMagic = 0x56475241;  // "VGRA"
constexpr int kVguestNumFds = 1;
constexpr int kVguestNumInts = 9;

struct VguestBufferHandle {
    native_handle_t base;
    int fd;
    int magic;
    int size;
    int width;
    int height;
    int stride;
    int format;
    int bpp;
    int usage;
    int flags;
};

struct LayerState {
    hwc2_layer_t id = 0;
    int32_t composition_type = HWC2_COMPOSITION_CLIENT;
};

struct VGuestHwcDevice {
    hwc2_device_t base {};

    std::mutex mu;
    uint8_t* fb_ring = nullptr;
    size_t fb_ring_size = 0;
    uint32_t width = kDefaultWidth;
    uint32_t height = kDefaultHeight;

    hwc2_callback_data_t hotplug_data = nullptr;
    HWC2_PFN_HOTPLUG hotplug_fn = nullptr;
    hwc2_callback_data_t refresh_data = nullptr;
    HWC2_PFN_REFRESH refresh_fn = nullptr;
    hwc2_callback_data_t vsync_data = nullptr;
    HWC2_PFN_VSYNC vsync_fn = nullptr;

    std::atomic<bool> vsync_enabled{false};
    std::atomic<bool> stop_vsync{false};
    pthread_t vsync_thread{};
    bool vsync_thread_started = false;

    hwc2_layer_t next_layer_id = 1;
    std::unordered_map<hwc2_layer_t, LayerState> layers;
    std::vector<hwc2_layer_t> changed_layers;

    buffer_handle_t client_target = nullptr;
    uint64_t presented_frames = 0;
};

VGuestHwcDevice* to_dev(hwc2_device_t* dev) {
    return reinterpret_cast<VGuestHwcDevice*>(dev);
}

void try_open_fb_ring_locked(VGuestHwcDevice* d) {
    if (d->fb_ring != nullptr) return;
    int fd = ::open("/tmp/.vguest_fb_ring", O_RDWR | O_CLOEXEC);
    if (fd < 0) return;

    struct stat st {};
    if (::fstat(fd, &st) != 0 || static_cast<size_t>(st.st_size) < vguest::fb::kFbHeaderSize) {
        ::close(fd);
        return;
    }

    void* map = ::mmap(nullptr, static_cast<size_t>(st.st_size), PROT_READ | PROT_WRITE,
                       MAP_SHARED, fd, 0);
    ::close(fd);
    if (map == MAP_FAILED) return;

    auto* hdr = reinterpret_cast<vguest::fb::VirtFbHeader*>(map);
    if (std::memcmp(hdr->magic, vguest::fb::kFbMagic, 4) != 0 || hdr->width == 0 || hdr->height == 0) {
        ::munmap(map, static_cast<size_t>(st.st_size));
        return;
    }

    d->fb_ring = reinterpret_cast<uint8_t*>(map);
    d->fb_ring_size = static_cast<size_t>(st.st_size);
    d->width = hdr->width;
    d->height = hdr->height;
}

void* vsync_thread_main(void* arg) {
    auto* d = reinterpret_cast<VGuestHwcDevice*>(arg);
    struct timespec next_ts {};
    ::clock_gettime(CLOCK_MONOTONIC, &next_ts);

    while (!d->stop_vsync.load(std::memory_order_acquire)) {
        next_ts.tv_nsec += kVsyncPeriodNs;
        if (next_ts.tv_nsec >= 1000000000L) {
            next_ts.tv_sec += 1;
            next_ts.tv_nsec -= 1000000000L;
        }
        ::clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &next_ts, nullptr);

        if (d->vsync_enabled.load(std::memory_order_acquire)) {
            HWC2_PFN_VSYNC fn = nullptr;
            hwc2_callback_data_t cb_data = nullptr;
            {
                std::lock_guard<std::mutex> lk(d->mu);
                fn = d->vsync_fn;
                cb_data = d->vsync_data;
            }
            if (fn) {
                struct timespec now {};
                ::clock_gettime(CLOCK_MONOTONIC, &now);
                int64_t ts_ns = static_cast<int64_t>(now.tv_sec) * 1000000000LL + now.tv_nsec;
                fn(cb_data, kPrimaryDisplayId, ts_ns);
            }
        }
    }
    return nullptr;
}

int32_t hwc_accept_display_changes(hwc2_device_t* dev, hwc2_display_t display) {
    if (display != kPrimaryDisplayId) return HWC2_ERROR_BAD_DISPLAY;
    auto* d = to_dev(dev);
    std::lock_guard<std::mutex> lk(d->mu);
    for (hwc2_layer_t lid : d->changed_layers) {
        auto it = d->layers.find(lid);
        if (it != d->layers.end()) {
            it->second.composition_type = HWC2_COMPOSITION_CLIENT;
        }
    }
    d->changed_layers.clear();
    return HWC2_ERROR_NONE;
}

int32_t hwc_create_layer(hwc2_device_t* dev, hwc2_display_t display, hwc2_layer_t* outLayer) {
    if (display != kPrimaryDisplayId) return HWC2_ERROR_BAD_DISPLAY;
    if (!outLayer) return HWC2_ERROR_BAD_PARAMETER;
    auto* d = to_dev(dev);
    std::lock_guard<std::mutex> lk(d->mu);
    hwc2_layer_t id = d->next_layer_id++;
    d->layers[id] = LayerState{id, HWC2_COMPOSITION_CLIENT};
    *outLayer = id;
    return HWC2_ERROR_NONE;
}

int32_t hwc_create_virtual_display(hwc2_device_t*, uint32_t, uint32_t, int32_t*, hwc2_display_t*) {
    return HWC2_ERROR_NO_RESOURCES;
}

int32_t hwc_destroy_layer(hwc2_device_t* dev, hwc2_display_t display, hwc2_layer_t layer) {
    if (display != kPrimaryDisplayId) return HWC2_ERROR_BAD_DISPLAY;
    auto* d = to_dev(dev);
    std::lock_guard<std::mutex> lk(d->mu);
    d->layers.erase(layer);
    return HWC2_ERROR_NONE;
}

int32_t hwc_destroy_virtual_display(hwc2_device_t*, hwc2_display_t) {
    return HWC2_ERROR_BAD_DISPLAY;
}

void hwc_dump(hwc2_device_t* dev, uint32_t* outSize, char* outBuffer) {
    auto* d = to_dev(dev);
    char msg[256];
    int n = std::snprintf(msg, sizeof(msg),
                          "VGuest Virtual HWC2: %ux%u@60Hz frames=%llu fb_mapped=%d\n",
                          d->width, d->height,
                          static_cast<unsigned long long>(d->presented_frames),
                          d->fb_ring ? 1 : 0);
    if (n < 0) n = 0;
    if (!outBuffer) {
        if (outSize) *outSize = static_cast<uint32_t>(n);
    } else if (outSize) {
        uint32_t to_copy = (*outSize < static_cast<uint32_t>(n)) ? *outSize : static_cast<uint32_t>(n);
        std::memcpy(outBuffer, msg, to_copy);
        *outSize = to_copy;
    }
}

uint32_t hwc_get_max_virtual_display_count(hwc2_device_t*) {
    return 0;
}

int32_t hwc_get_active_config(hwc2_device_t*, hwc2_display_t display, hwc2_config_t* outConfig) {
    if (display != kPrimaryDisplayId) return HWC2_ERROR_BAD_DISPLAY;
    if (!outConfig) return HWC2_ERROR_BAD_PARAMETER;
    *outConfig = kPrimaryConfigId;
    return HWC2_ERROR_NONE;
}

int32_t hwc_get_changed_composition_types(hwc2_device_t* dev, hwc2_display_t display,
                                          uint32_t* outNumElements, hwc2_layer_t* outLayers,
                                          int32_t* outTypes) {
    if (display != kPrimaryDisplayId) return HWC2_ERROR_BAD_DISPLAY;
    if (!outNumElements) return HWC2_ERROR_BAD_PARAMETER;
    auto* d = to_dev(dev);
    std::lock_guard<std::mutex> lk(d->mu);
    if (!outLayers || !outTypes) {
        *outNumElements = static_cast<uint32_t>(d->changed_layers.size());
        return HWC2_ERROR_NONE;
    }
    uint32_t count = static_cast<uint32_t>(d->changed_layers.size());
    if (*outNumElements < count) count = *outNumElements;
    for (uint32_t i = 0; i < count; ++i) {
        outLayers[i] = d->changed_layers[i];
        outTypes[i] = HWC2_COMPOSITION_CLIENT;
    }
    *outNumElements = count;
    return HWC2_ERROR_NONE;
}

int32_t hwc_get_client_target_support(hwc2_device_t*, hwc2_display_t display, uint32_t, uint32_t,
                                      int32_t, int32_t) {
    if (display != kPrimaryDisplayId) return HWC2_ERROR_BAD_DISPLAY;
    return HWC2_ERROR_NONE;
}

int32_t hwc_get_color_modes(hwc2_device_t*, hwc2_display_t display, uint32_t* outNumModes,
                            int32_t* outModes) {
    if (display != kPrimaryDisplayId) return HWC2_ERROR_BAD_DISPLAY;
    if (!outNumModes) return HWC2_ERROR_BAD_PARAMETER;
    if (!outModes) {
        *outNumModes = 1;
        return HWC2_ERROR_NONE;
    }
    if (*outNumModes >= 1) {
        outModes[0] = HAL_COLOR_MODE_NATIVE;
        *outNumModes = 1;
    }
    return HWC2_ERROR_NONE;
}

int32_t hwc_get_display_attribute(hwc2_device_t* dev, hwc2_display_t display, hwc2_config_t config,
                                  int32_t attribute, int32_t* outValue) {
    if (display != kPrimaryDisplayId) return HWC2_ERROR_BAD_DISPLAY;
    if (config != kPrimaryConfigId) return HWC2_ERROR_BAD_CONFIG;
    if (!outValue) return HWC2_ERROR_BAD_PARAMETER;
    auto* d = to_dev(dev);
    switch (attribute) {
        case HWC2_ATTRIBUTE_WIDTH:
            *outValue = static_cast<int32_t>(d->width);
            return HWC2_ERROR_NONE;
        case HWC2_ATTRIBUTE_HEIGHT:
            *outValue = static_cast<int32_t>(d->height);
            return HWC2_ERROR_NONE;
        case HWC2_ATTRIBUTE_VSYNC_PERIOD:
            *outValue = kVsyncPeriodNs;
            return HWC2_ERROR_NONE;
        case HWC2_ATTRIBUTE_DPI_X:
        case HWC2_ATTRIBUTE_DPI_Y:
            *outValue = kDpiScaled;
            return HWC2_ERROR_NONE;
        default:
            return HWC2_ERROR_BAD_PARAMETER;
    }
}

int32_t hwc_get_display_configs(hwc2_device_t*, hwc2_display_t display, uint32_t* outNumConfigs,
                                hwc2_config_t* outConfigs) {
    if (display != kPrimaryDisplayId) return HWC2_ERROR_BAD_DISPLAY;
    if (!outNumConfigs) return HWC2_ERROR_BAD_PARAMETER;
    if (!outConfigs) {
        *outNumConfigs = 1;
        return HWC2_ERROR_NONE;
    }
    if (*outNumConfigs >= 1) {
        outConfigs[0] = kPrimaryConfigId;
        *outNumConfigs = 1;
    }
    return HWC2_ERROR_NONE;
}

int32_t hwc_get_display_name(hwc2_device_t*, hwc2_display_t display, uint32_t* outSize,
                             char* outName) {
    if (display != kPrimaryDisplayId) return HWC2_ERROR_BAD_DISPLAY;
    if (!outSize) return HWC2_ERROR_BAD_PARAMETER;
    const char* name = "VGuest Virtual Display";
    uint32_t len = static_cast<uint32_t>(std::strlen(name));
    if (!outName) {
        *outSize = len;
        return HWC2_ERROR_NONE;
    }
    uint32_t n = (*outSize < len) ? *outSize : len;
    std::memcpy(outName, name, n);
    *outSize = n;
    return HWC2_ERROR_NONE;
}

int32_t hwc_get_display_requests(hwc2_device_t*, hwc2_display_t display,
                                 int32_t* outDisplayRequests, uint32_t* outNumElements,
                                 hwc2_layer_t*, int32_t*) {
    if (display != kPrimaryDisplayId) return HWC2_ERROR_BAD_DISPLAY;
    if (outDisplayRequests) *outDisplayRequests = 0;
    if (outNumElements) *outNumElements = 0;
    return HWC2_ERROR_NONE;
}

int32_t hwc_get_display_type(hwc2_device_t*, hwc2_display_t display, int32_t* outType) {
    if (display != kPrimaryDisplayId) return HWC2_ERROR_BAD_DISPLAY;
    if (!outType) return HWC2_ERROR_BAD_PARAMETER;
    *outType = HWC2_DISPLAY_TYPE_PHYSICAL;
    return HWC2_ERROR_NONE;
}

int32_t hwc_get_doze_support(hwc2_device_t*, hwc2_display_t display, int32_t* outSupport) {
    if (display != kPrimaryDisplayId) return HWC2_ERROR_BAD_DISPLAY;
    if (outSupport) *outSupport = 0;
    return HWC2_ERROR_NONE;
}

int32_t hwc_get_hdr_capabilities(hwc2_device_t*, hwc2_display_t display, uint32_t* outNumTypes,
                                 int32_t*, float* outMaxLuminance, float* outMaxAverageLuminance,
                                 float* outMinLuminance) {
    if (display != kPrimaryDisplayId) return HWC2_ERROR_BAD_DISPLAY;
    if (outNumTypes) *outNumTypes = 0;
    if (outMaxLuminance) *outMaxLuminance = 0.0f;
    if (outMaxAverageLuminance) *outMaxAverageLuminance = 0.0f;
    if (outMinLuminance) *outMinLuminance = 0.0f;
    return HWC2_ERROR_NONE;
}

int32_t hwc_get_release_fences(hwc2_device_t*, hwc2_display_t display, uint32_t* outNumElements,
                               hwc2_layer_t*, int32_t*) {
    if (display != kPrimaryDisplayId) return HWC2_ERROR_BAD_DISPLAY;
    if (outNumElements) *outNumElements = 0;
    return HWC2_ERROR_NONE;
}

int32_t hwc_present_display(hwc2_device_t* dev, hwc2_display_t display, int32_t* outPresentFence) {
    if (display != kPrimaryDisplayId) return HWC2_ERROR_BAD_DISPLAY;
    if (outPresentFence) *outPresentFence = -1;

    auto* d = to_dev(dev);
    std::lock_guard<std::mutex> lk(d->mu);
    try_open_fb_ring_locked(d);
    if (!d->fb_ring || !d->client_target) {
        d->presented_frames++;
        return HWC2_ERROR_NONE;
    }

    const native_handle_t* hnd = d->client_target;
    if (hnd->numFds == kVguestNumFds && hnd->numInts == kVguestNumInts) {
        const auto* vh = reinterpret_cast<const VguestBufferHandle*>(hnd);
        if (vh->magic == kVguestGrallocMagic && vh->fd >= 0 && vh->size > 0) {
            void* src_map = ::mmap(nullptr, static_cast<size_t>(vh->size), PROT_READ, MAP_SHARED,
                                   vh->fd, 0);
            if (src_map != MAP_FAILED) {
                auto* hdr = reinterpret_cast<vguest::fb::VirtFbHeader*>(d->fb_ring);
                int slot = vguest::fb::acquire_write_slot(hdr);
                if (slot >= 0) {
                    uint8_t* dst = vguest::fb::slot_pixel_ptr(d->fb_ring, hdr,
                                                              static_cast<uint32_t>(slot));
                    const auto* src = reinterpret_cast<const uint8_t*>(src_map);
                    uint32_t copy_w = (static_cast<uint32_t>(vh->width) < hdr->width)
                                          ? static_cast<uint32_t>(vh->width)
                                          : hdr->width;
                    uint32_t copy_h = (static_cast<uint32_t>(vh->height) < hdr->height)
                                          ? static_cast<uint32_t>(vh->height)
                                          : hdr->height;
                    size_t row_bytes = static_cast<size_t>(copy_w) * 4u;
                    size_t src_stride_bytes = static_cast<size_t>(vh->stride) *
                                              static_cast<size_t>(vh->bpp > 0 ? vh->bpp : 4);
                    for (uint32_t y = 0; y < copy_h; ++y) {
                        std::memcpy(dst + y * hdr->stride_bytes, src + y * src_stride_bytes,
                                    row_bytes);
                    }
                    vguest::fb::present_write_slot(hdr, static_cast<uint32_t>(slot));
                }
                ::munmap(src_map, static_cast<size_t>(vh->size));
            }
        }
    }

    d->presented_frames++;
    return HWC2_ERROR_NONE;
}

int32_t hwc_register_callback(hwc2_device_t* dev, int32_t descriptor,
                              hwc2_callback_data_t callbackData, hwc2_function_pointer_t pointer) {
    auto* d = to_dev(dev);
    HWC2_PFN_HOTPLUG fire_hotplug = nullptr;
    {
        std::lock_guard<std::mutex> lk(d->mu);
        switch (descriptor) {
            case HWC2_CALLBACK_HOTPLUG:
                d->hotplug_data = callbackData;
                d->hotplug_fn = reinterpret_cast<HWC2_PFN_HOTPLUG>(pointer);
                fire_hotplug = d->hotplug_fn;
                break;
            case HWC2_CALLBACK_REFRESH:
                d->refresh_data = callbackData;
                d->refresh_fn = reinterpret_cast<HWC2_PFN_REFRESH>(pointer);
                break;
            case HWC2_CALLBACK_VSYNC:
                d->vsync_data = callbackData;
                d->vsync_fn = reinterpret_cast<HWC2_PFN_VSYNC>(pointer);
                break;
            default:
                return HWC2_ERROR_BAD_PARAMETER;
        }
    }
    if (fire_hotplug) {
        fire_hotplug(callbackData, kPrimaryDisplayId, HWC2_CONNECTION_CONNECTED);
    }
    return HWC2_ERROR_NONE;
}

int32_t hwc_set_active_config(hwc2_device_t*, hwc2_display_t display, hwc2_config_t config) {
    if (display != kPrimaryDisplayId) return HWC2_ERROR_BAD_DISPLAY;
    if (config != kPrimaryConfigId) return HWC2_ERROR_BAD_CONFIG;
    return HWC2_ERROR_NONE;
}

int32_t hwc_set_client_target(hwc2_device_t* dev, hwc2_display_t display, buffer_handle_t target,
                              int32_t acquireFence, int32_t, hwc_region_t) {
    if (acquireFence >= 0) ::close(acquireFence);
    if (display != kPrimaryDisplayId) return HWC2_ERROR_BAD_DISPLAY;
    auto* d = to_dev(dev);
    std::lock_guard<std::mutex> lk(d->mu);
    d->client_target = target;
    return HWC2_ERROR_NONE;
}

int32_t hwc_set_color_mode(hwc2_device_t*, hwc2_display_t display, int32_t) {
    return (display == kPrimaryDisplayId) ? HWC2_ERROR_NONE : HWC2_ERROR_BAD_DISPLAY;
}

int32_t hwc_set_color_transform(hwc2_device_t*, hwc2_display_t display, const float*, int32_t) {
    return (display == kPrimaryDisplayId) ? HWC2_ERROR_NONE : HWC2_ERROR_BAD_DISPLAY;
}

int32_t hwc_set_output_buffer(hwc2_device_t*, hwc2_display_t, buffer_handle_t, int32_t fence) {
    if (fence >= 0) ::close(fence);
    return HWC2_ERROR_UNSUPPORTED;
}

int32_t hwc_set_power_mode(hwc2_device_t*, hwc2_display_t display, int32_t) {
    return (display == kPrimaryDisplayId) ? HWC2_ERROR_NONE : HWC2_ERROR_BAD_DISPLAY;
}

int32_t hwc_set_vsync_enabled(hwc2_device_t* dev, hwc2_display_t display, int32_t enabled) {
    if (display != kPrimaryDisplayId) return HWC2_ERROR_BAD_DISPLAY;
    to_dev(dev)->vsync_enabled.store(enabled == HWC2_VSYNC_ENABLE, std::memory_order_release);
    return HWC2_ERROR_NONE;
}

int32_t hwc_validate_display(hwc2_device_t* dev, hwc2_display_t display, uint32_t* outNumTypes,
                             uint32_t* outNumRequests) {
    if (display != kPrimaryDisplayId) return HWC2_ERROR_BAD_DISPLAY;
    auto* d = to_dev(dev);
    std::lock_guard<std::mutex> lk(d->mu);
    d->changed_layers.clear();
    for (const auto& kv : d->layers) {
        if (kv.second.composition_type != HWC2_COMPOSITION_CLIENT) {
            d->changed_layers.push_back(kv.first);
        }
    }
    if (outNumTypes) *outNumTypes = static_cast<uint32_t>(d->changed_layers.size());
    if (outNumRequests) *outNumRequests = 0;
    return d->changed_layers.empty() ? HWC2_ERROR_NONE : HWC2_ERROR_HAS_CHANGES;
}

int32_t hwc_set_layer_composition_type(hwc2_device_t* dev, hwc2_display_t display,
                                       hwc2_layer_t layer, int32_t type) {
    if (display != kPrimaryDisplayId) return HWC2_ERROR_BAD_DISPLAY;
    auto* d = to_dev(dev);
    std::lock_guard<std::mutex> lk(d->mu);
    auto it = d->layers.find(layer);
    if (it == d->layers.end()) return HWC2_ERROR_BAD_LAYER;
    it->second.composition_type = type;
    return HWC2_ERROR_NONE;
}

int32_t hwc_set_layer_buffer(hwc2_device_t*, hwc2_display_t display, hwc2_layer_t, buffer_handle_t,
                             int32_t acquireFence) {
    if (acquireFence >= 0) ::close(acquireFence);
    return (display == kPrimaryDisplayId) ? HWC2_ERROR_NONE : HWC2_ERROR_BAD_DISPLAY;
}

int32_t hwc_set_layer_cursor_position(hwc2_device_t*, hwc2_display_t display, hwc2_layer_t, int32_t,
                                      int32_t) {
    return (display == kPrimaryDisplayId) ? HWC2_ERROR_NONE : HWC2_ERROR_BAD_DISPLAY;
}

int32_t hwc_set_layer_surface_damage(hwc2_device_t*, hwc2_display_t display, hwc2_layer_t,
                                     hwc_region_t) {
    return (display == kPrimaryDisplayId) ? HWC2_ERROR_NONE : HWC2_ERROR_BAD_DISPLAY;
}

int32_t hwc_set_layer_blend_mode(hwc2_device_t*, hwc2_display_t display, hwc2_layer_t, int32_t) {
    return (display == kPrimaryDisplayId) ? HWC2_ERROR_NONE : HWC2_ERROR_BAD_DISPLAY;
}

int32_t hwc_set_layer_color(hwc2_device_t*, hwc2_display_t display, hwc2_layer_t, hwc_color_t) {
    return (display == kPrimaryDisplayId) ? HWC2_ERROR_NONE : HWC2_ERROR_BAD_DISPLAY;
}

int32_t hwc_set_layer_dataspace(hwc2_device_t*, hwc2_display_t display, hwc2_layer_t, int32_t) {
    return (display == kPrimaryDisplayId) ? HWC2_ERROR_NONE : HWC2_ERROR_BAD_DISPLAY;
}

int32_t hwc_set_layer_display_frame(hwc2_device_t*, hwc2_display_t display, hwc2_layer_t,
                                    hwc_rect_t) {
    return (display == kPrimaryDisplayId) ? HWC2_ERROR_NONE : HWC2_ERROR_BAD_DISPLAY;
}

int32_t hwc_set_layer_plane_alpha(hwc2_device_t*, hwc2_display_t display, hwc2_layer_t, float) {
    return (display == kPrimaryDisplayId) ? HWC2_ERROR_NONE : HWC2_ERROR_BAD_DISPLAY;
}

int32_t hwc_set_layer_sideband_stream(hwc2_device_t*, hwc2_display_t display, hwc2_layer_t,
                                      const native_handle_t*) {
    return (display == kPrimaryDisplayId) ? HWC2_ERROR_UNSUPPORTED : HWC2_ERROR_BAD_DISPLAY;
}

int32_t hwc_set_layer_source_crop(hwc2_device_t*, hwc2_display_t display, hwc2_layer_t,
                                  hwc_frect_t) {
    return (display == kPrimaryDisplayId) ? HWC2_ERROR_NONE : HWC2_ERROR_BAD_DISPLAY;
}

int32_t hwc_set_layer_transform(hwc2_device_t*, hwc2_display_t display, hwc2_layer_t, int32_t) {
    return (display == kPrimaryDisplayId) ? HWC2_ERROR_NONE : HWC2_ERROR_BAD_DISPLAY;
}

int32_t hwc_set_layer_visible_region(hwc2_device_t*, hwc2_display_t display, hwc2_layer_t,
                                     hwc_region_t) {
    return (display == kPrimaryDisplayId) ? HWC2_ERROR_NONE : HWC2_ERROR_BAD_DISPLAY;
}

int32_t hwc_set_layer_z_order(hwc2_device_t*, hwc2_display_t display, hwc2_layer_t, uint32_t) {
    return (display == kPrimaryDisplayId) ? HWC2_ERROR_NONE : HWC2_ERROR_BAD_DISPLAY;
}

void hwc_get_capabilities(hwc2_device_t*, uint32_t* outCount, int32_t*) {
    if (outCount) *outCount = 0;
}

hwc2_function_pointer_t hwc_get_function(hwc2_device_t*, int32_t descriptor) {
    switch (descriptor) {
        case HWC2_FUNCTION_ACCEPT_DISPLAY_CHANGES:
            return reinterpret_cast<hwc2_function_pointer_t>(hwc_accept_display_changes);
        case HWC2_FUNCTION_CREATE_LAYER:
            return reinterpret_cast<hwc2_function_pointer_t>(hwc_create_layer);
        case HWC2_FUNCTION_CREATE_VIRTUAL_DISPLAY:
            return reinterpret_cast<hwc2_function_pointer_t>(hwc_create_virtual_display);
        case HWC2_FUNCTION_DESTROY_LAYER:
            return reinterpret_cast<hwc2_function_pointer_t>(hwc_destroy_layer);
        case HWC2_FUNCTION_DESTROY_VIRTUAL_DISPLAY:
            return reinterpret_cast<hwc2_function_pointer_t>(hwc_destroy_virtual_display);
        case HWC2_FUNCTION_DUMP:
            return reinterpret_cast<hwc2_function_pointer_t>(hwc_dump);
        case HWC2_FUNCTION_GET_ACTIVE_CONFIG:
            return reinterpret_cast<hwc2_function_pointer_t>(hwc_get_active_config);
        case HWC2_FUNCTION_GET_CHANGED_COMPOSITION_TYPES:
            return reinterpret_cast<hwc2_function_pointer_t>(hwc_get_changed_composition_types);
        case HWC2_FUNCTION_GET_CLIENT_TARGET_SUPPORT:
            return reinterpret_cast<hwc2_function_pointer_t>(hwc_get_client_target_support);
        case HWC2_FUNCTION_GET_COLOR_MODES:
            return reinterpret_cast<hwc2_function_pointer_t>(hwc_get_color_modes);
        case HWC2_FUNCTION_GET_DISPLAY_ATTRIBUTE:
            return reinterpret_cast<hwc2_function_pointer_t>(hwc_get_display_attribute);
        case HWC2_FUNCTION_GET_DISPLAY_CONFIGS:
            return reinterpret_cast<hwc2_function_pointer_t>(hwc_get_display_configs);
        case HWC2_FUNCTION_GET_DISPLAY_NAME:
            return reinterpret_cast<hwc2_function_pointer_t>(hwc_get_display_name);
        case HWC2_FUNCTION_GET_DISPLAY_REQUESTS:
            return reinterpret_cast<hwc2_function_pointer_t>(hwc_get_display_requests);
        case HWC2_FUNCTION_GET_DISPLAY_TYPE:
            return reinterpret_cast<hwc2_function_pointer_t>(hwc_get_display_type);
        case HWC2_FUNCTION_GET_DOZE_SUPPORT:
            return reinterpret_cast<hwc2_function_pointer_t>(hwc_get_doze_support);
        case HWC2_FUNCTION_GET_HDR_CAPABILITIES:
            return reinterpret_cast<hwc2_function_pointer_t>(hwc_get_hdr_capabilities);
        case HWC2_FUNCTION_GET_MAX_VIRTUAL_DISPLAY_COUNT:
            return reinterpret_cast<hwc2_function_pointer_t>(hwc_get_max_virtual_display_count);
        case HWC2_FUNCTION_GET_RELEASE_FENCES:
            return reinterpret_cast<hwc2_function_pointer_t>(hwc_get_release_fences);
        case HWC2_FUNCTION_PRESENT_DISPLAY:
            return reinterpret_cast<hwc2_function_pointer_t>(hwc_present_display);
        case HWC2_FUNCTION_REGISTER_CALLBACK:
            return reinterpret_cast<hwc2_function_pointer_t>(hwc_register_callback);
        case HWC2_FUNCTION_SET_ACTIVE_CONFIG:
            return reinterpret_cast<hwc2_function_pointer_t>(hwc_set_active_config);
        case HWC2_FUNCTION_SET_CLIENT_TARGET:
            return reinterpret_cast<hwc2_function_pointer_t>(hwc_set_client_target);
        case HWC2_FUNCTION_SET_COLOR_MODE:
            return reinterpret_cast<hwc2_function_pointer_t>(hwc_set_color_mode);
        case HWC2_FUNCTION_SET_COLOR_TRANSFORM:
            return reinterpret_cast<hwc2_function_pointer_t>(hwc_set_color_transform);
        case HWC2_FUNCTION_SET_CURSOR_POSITION:
            return reinterpret_cast<hwc2_function_pointer_t>(hwc_set_layer_cursor_position);
        case HWC2_FUNCTION_SET_LAYER_BLEND_MODE:
            return reinterpret_cast<hwc2_function_pointer_t>(hwc_set_layer_blend_mode);
        case HWC2_FUNCTION_SET_LAYER_BUFFER:
            return reinterpret_cast<hwc2_function_pointer_t>(hwc_set_layer_buffer);
        case HWC2_FUNCTION_SET_LAYER_COLOR:
            return reinterpret_cast<hwc2_function_pointer_t>(hwc_set_layer_color);
        case HWC2_FUNCTION_SET_LAYER_COMPOSITION_TYPE:
            return reinterpret_cast<hwc2_function_pointer_t>(hwc_set_layer_composition_type);
        case HWC2_FUNCTION_SET_LAYER_DATASPACE:
            return reinterpret_cast<hwc2_function_pointer_t>(hwc_set_layer_dataspace);
        case HWC2_FUNCTION_SET_LAYER_DISPLAY_FRAME:
            return reinterpret_cast<hwc2_function_pointer_t>(hwc_set_layer_display_frame);
        case HWC2_FUNCTION_SET_LAYER_PLANE_ALPHA:
            return reinterpret_cast<hwc2_function_pointer_t>(hwc_set_layer_plane_alpha);
        case HWC2_FUNCTION_SET_LAYER_SIDEBAND_STREAM:
            return reinterpret_cast<hwc2_function_pointer_t>(hwc_set_layer_sideband_stream);
        case HWC2_FUNCTION_SET_LAYER_SOURCE_CROP:
            return reinterpret_cast<hwc2_function_pointer_t>(hwc_set_layer_source_crop);
        case HWC2_FUNCTION_SET_LAYER_SURFACE_DAMAGE:
            return reinterpret_cast<hwc2_function_pointer_t>(hwc_set_layer_surface_damage);
        case HWC2_FUNCTION_SET_LAYER_TRANSFORM:
            return reinterpret_cast<hwc2_function_pointer_t>(hwc_set_layer_transform);
        case HWC2_FUNCTION_SET_LAYER_VISIBLE_REGION:
            return reinterpret_cast<hwc2_function_pointer_t>(hwc_set_layer_visible_region);
        case HWC2_FUNCTION_SET_LAYER_Z_ORDER:
            return reinterpret_cast<hwc2_function_pointer_t>(hwc_set_layer_z_order);
        case HWC2_FUNCTION_SET_OUTPUT_BUFFER:
            return reinterpret_cast<hwc2_function_pointer_t>(hwc_set_output_buffer);
        case HWC2_FUNCTION_SET_POWER_MODE:
            return reinterpret_cast<hwc2_function_pointer_t>(hwc_set_power_mode);
        case HWC2_FUNCTION_SET_VSYNC_ENABLED:
            return reinterpret_cast<hwc2_function_pointer_t>(hwc_set_vsync_enabled);
        case HWC2_FUNCTION_VALIDATE_DISPLAY:
            return reinterpret_cast<hwc2_function_pointer_t>(hwc_validate_display);
        default:
            return nullptr;
    }
}

int hwc_close(struct hw_device_t* device) {
    auto* d = reinterpret_cast<VGuestHwcDevice*>(device);
    if (!d) return 0;
    d->stop_vsync.store(true, std::memory_order_release);
    if (d->vsync_thread_started) {
        pthread_join(d->vsync_thread, nullptr);
    }
    if (d->fb_ring) {
        ::munmap(d->fb_ring, d->fb_ring_size);
        d->fb_ring = nullptr;
    }
    delete d;
    return 0;
}

int hwc_open(const struct hw_module_t* module, const char* id, struct hw_device_t** device) {
    if (!device || !id || std::strcmp(id, HWC_HARDWARE_COMPOSER) != 0) {
        return -EINVAL;
    }
    auto* d = new VGuestHwcDevice();
    d->base.common.tag = HARDWARE_DEVICE_TAG;
    d->base.common.version = HWC_DEVICE_API_VERSION_2_0;
    d->base.common.module = const_cast<hw_module_t*>(module);
    d->base.common.close = hwc_close;
    d->base.getCapabilities = hwc_get_capabilities;
    d->base.getFunction = hwc_get_function;

    {
        std::lock_guard<std::mutex> lk(d->mu);
        try_open_fb_ring_locked(d);
    }

    if (pthread_create(&d->vsync_thread, nullptr, vsync_thread_main, d) == 0) {
        d->vsync_thread_started = true;
    }

    *device = &d->base.common;
    return 0;
}

struct hw_module_methods_t g_hwc_methods = {
    .open = hwc_open,
};

}  // namespace

extern "C" __attribute__((visibility("default")))
hw_module_t HMI = {
    .tag = HARDWARE_MODULE_TAG,
    .module_api_version = HWC_MODULE_API_VERSION_0_1,
    .hal_api_version = HARDWARE_HAL_API_VERSION,
    .id = HWC_HARDWARE_MODULE_ID,
    .name = "VGuest Virtual HWC2 HAL",
    .author = "VGuest",
    .methods = &g_hwc_methods,
    .dso = nullptr,
    .reserved = {0},
};
