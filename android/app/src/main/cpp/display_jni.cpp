#include <android/log.h>
#include <android/native_window.h>
#include <android/native_window_jni.h>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <jni.h>
#include <mutex>
#include <string>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <thread>
#include <unistd.h>

#include "virt_fb_protocol.hpp"

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, "VGuestDisplay", __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "VGuestDisplay", __VA_ARGS__)

namespace {

struct HostInputPacket {
    uint32_t dev_idx;
    uint16_t type;
    uint16_t code;
    int32_t value;
};

std::mutex g_mu;
uint8_t* g_ring_map = nullptr;
size_t g_ring_size = 0;
uint32_t g_width = 1400;
uint32_t g_height = 876;
std::string g_input_sock_path;
int g_input_sock_fd = -1;

ANativeWindow* g_window = nullptr;
std::atomic<bool> g_render_running{false};
std::thread g_render_thread;

void stop_render_locked() {
    if (g_render_running.exchange(false)) {
        g_mu.unlock();
        if (g_render_thread.joinable()) g_render_thread.join();
        g_mu.lock();
    }
    if (g_window) {
        ANativeWindow_release(g_window);
        g_window = nullptr;
    }
}

void render_loop() {
    uint32_t last_seq = 0xFFFFFFFFU;
    while (g_render_running.load(std::memory_order_acquire)) {
        uint8_t* ring = nullptr;
        ANativeWindow* win = nullptr;
        {
            std::lock_guard<std::mutex> lk(g_mu);
            ring = g_ring_map;
            win = g_window;
        }
        if (!ring || !win) {
            ::usleep(8000);
            continue;
        }

        auto* hdr = reinterpret_cast<vguest::fb::VirtFbHeader*>(ring);
        uint32_t seq = hdr->frame_seq.load(std::memory_order_acquire);
        if (seq == last_seq) {
            ::usleep(2000);
            continue;
        }

        int slot = vguest::fb::acquire_ready_slot(hdr);
        if (slot < 0) {
            ::usleep(2000);
            continue;
        }

        ANativeWindow_Buffer buf {};
        if (ANativeWindow_lock(win, &buf, nullptr) == 0) {
            const uint8_t* src = vguest::fb::slot_pixel_ptr(ring, hdr, static_cast<uint32_t>(slot));
            auto* dst = reinterpret_cast<uint8_t*>(buf.bits);
            const uint32_t copy_w = (hdr->width < static_cast<uint32_t>(buf.width))
                                        ? hdr->width
                                        : static_cast<uint32_t>(buf.width);
            const uint32_t copy_h = (hdr->height < static_cast<uint32_t>(buf.height))
                                        ? hdr->height
                                        : static_cast<uint32_t>(buf.height);
            const size_t row_bytes = static_cast<size_t>(copy_w) * 4u;
            const size_t dst_stride = static_cast<size_t>(buf.stride) * 4u;

            for (uint32_t y = 0; y < copy_h; ++y) {
                std::memcpy(dst + y * dst_stride, src + y * hdr->stride_bytes, row_bytes);
            }
            ANativeWindow_unlockAndPost(win);
            last_seq = seq;
        }

        vguest::fb::release_display_slot(hdr, static_cast<uint32_t>(slot));
    }
}

}  // namespace

extern "C" JNIEXPORT jboolean JNICALL
Java_com_vguest_app_DisplayBridge_nativeInitDisplay(JNIEnv* env, jobject,
                                                    jstring j_rootfs,
                                                    jint width, jint height) {
    const char* c_rootfs = env->GetStringUTFChars(j_rootfs, nullptr);
    std::string rootfs(c_rootfs ? c_rootfs : "");
    env->ReleaseStringUTFChars(j_rootfs, c_rootfs);

    std::lock_guard<std::mutex> lk(g_mu);
    if (g_ring_map) {
        ::munmap(g_ring_map, g_ring_size);
        g_ring_map = nullptr;
    }

    g_width = static_cast<uint32_t>(width);
    g_height = static_cast<uint32_t>(height);
    g_ring_size = vguest::fb::compute_ring_total_size(g_width, g_height);
    g_input_sock_path = rootfs + "/dev/socket/vguest_input";

    std::string tmp_dir = rootfs + "/tmp";
    ::mkdir(tmp_dir.c_str(), 0755);
    std::string ring_path = tmp_dir + "/.vguest_fb_ring";

    int fd = ::open(ring_path.c_str(), O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
    if (fd < 0) {
        LOGE("Failed to create %s", ring_path.c_str());
        return JNI_FALSE;
    }
    if (::ftruncate(fd, static_cast<off_t>(g_ring_size)) != 0) {
        ::close(fd);
        return JNI_FALSE;
    }

    void* map = ::mmap(nullptr, g_ring_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    ::close(fd);
    if (map == MAP_FAILED) return JNI_FALSE;

    g_ring_map = reinterpret_cast<uint8_t*>(map);
    vguest::fb::init_fb_header(reinterpret_cast<vguest::fb::VirtFbHeader*>(g_ring_map),
                               g_width, g_height);

    if (g_input_sock_fd < 0) {
        g_input_sock_fd = ::socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    }

    LOGI("Initialized shared framebuffer ring %ux%u (%zu bytes)", g_width, g_height, g_ring_size);
    return JNI_TRUE;
}

extern "C" JNIEXPORT void JNICALL
Java_com_vguest_app_DisplayBridge_nativeAttachSurface(JNIEnv* env, jobject, jobject j_surface) {
    std::lock_guard<std::mutex> lk(g_mu);
    stop_render_locked();

    ANativeWindow* win = ANativeWindow_fromSurface(env, j_surface);
    if (!win) return;

    ANativeWindow_setBuffersGeometry(win, static_cast<int32_t>(g_width),
                                     static_cast<int32_t>(g_height),
                                     WINDOW_FORMAT_RGBA_8888);
    g_window = win;
    g_render_running.store(true, std::memory_order_release);
    g_render_thread = std::thread(render_loop);
    LOGI("Attached ANativeWindow %ux%u", g_width, g_height);
}

extern "C" JNIEXPORT void JNICALL
Java_com_vguest_app_DisplayBridge_nativeDetachSurface(JNIEnv*, jobject) {
    std::lock_guard<std::mutex> lk(g_mu);
    stop_render_locked();
}

extern "C" JNIEXPORT void JNICALL
Java_com_vguest_app_DisplayBridge_nativeInjectInput(JNIEnv*, jobject,
                                                    jint dev_idx, jint type,
                                                    jint code, jint value) {
    if (g_input_sock_fd < 0 || g_input_sock_path.empty()) return;

    struct sockaddr_un addr {};
    addr.sun_family = AF_UNIX;
    if (g_input_sock_path.size() >= sizeof(addr.sun_path)) return;
    std::strncpy(addr.sun_path, g_input_sock_path.c_str(), sizeof(addr.sun_path) - 1);

    HostInputPacket pkt {
        static_cast<uint32_t>(dev_idx),
        static_cast<uint16_t>(type),
        static_cast<uint16_t>(code),
        static_cast<int32_t>(value),
    };
    (void)::sendto(g_input_sock_fd, &pkt, sizeof(pkt), MSG_DONTWAIT,
                   reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
}
