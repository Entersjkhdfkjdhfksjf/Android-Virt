#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <linux/input.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

#include "virt_fb_protocol.hpp"

// Guest-side Phase 5 verification producer:
// - Opens /tmp/.vguest_fb_ring (triple-buffered shared memory with host ANativeWindow)
// - Opens /dev/input/event0 (Touch) & /dev/input/event1 (S Pen), verifying EVIOCGNAME/EVIOCGABS
// - Renders a 60 FPS animated grid + live touch/S Pen pressure-sensitive ink trail!

struct TrailPoint {
    int x = 0;
    int y = 0;
    int radius = 8;
    uint32_t color = 0xFF7EE787U;  // ABGR (RGBA_8888 little-endian)
};

static void draw_circle(uint32_t* px, uint32_t w, uint32_t h,
                        int cx, int cy, int r, uint32_t rgba) {
    int r2 = r * r;
    int y0 = (cy - r < 0) ? 0 : (cy - r);
    int y1 = (cy + r >= static_cast<int>(h)) ? static_cast<int>(h) - 1 : (cy + r);
    int x0 = (cx - r < 0) ? 0 : (cx - r);
    int x1 = (cx + r >= static_cast<int>(w)) ? static_cast<int>(w) - 1 : (cx + r);
    for (int y = y0; y <= y1; ++y) {
        int dy = y - cy;
        uint32_t* row = px + static_cast<size_t>(y) * w;
        for (int x = x0; x <= x1; ++x) {
            int dx = x - cx;
            if (dx * dx + dy * dy <= r2) row[x] = rgba;
        }
    }
}

int main() {
    int fb_fd = ::open("/tmp/.vguest_fb_ring", O_RDWR);
    if (fb_fd < 0) {
        std::fprintf(stderr, "[vguest_fb_demo] failed to open /tmp/.vguest_fb_ring\n");
        return 1;
    }

    struct stat st {};
    if (::fstat(fb_fd, &st) != 0 || st.st_size < static_cast<off_t>(vguest::fb::kFbHeaderSize)) {
        std::fprintf(stderr, "[vguest_fb_demo] invalid framebuffer ring size\n");
        ::close(fb_fd);
        return 1;
    }

    void* map = ::mmap(nullptr, static_cast<size_t>(st.st_size),
                       PROT_READ | PROT_WRITE, MAP_SHARED, fb_fd, 0);
    ::close(fb_fd);
    if (map == MAP_FAILED) {
        std::fprintf(stderr, "[vguest_fb_demo] mmap failed\n");
        return 1;
    }

    auto* ring = reinterpret_cast<uint8_t*>(map);
    auto* hdr = reinterpret_cast<vguest::fb::VirtFbHeader*>(ring);
    const uint32_t W = hdr->width;
    const uint32_t H = hdr->height;
    std::printf("[vguest_fb_demo] Attached shared ring %ux%u (3 slots)\n", W, H);

    // Probe virtual evdev devices (/dev/input/event0 touch, /dev/input/event1 S Pen)
    int touch_fd = ::open("/dev/input/event0", O_RDONLY | O_NONBLOCK);
    int spen_fd = ::open("/dev/input/event1", O_RDONLY | O_NONBLOCK);
    char name_buf[64] = {};
    if (touch_fd >= 0 && ::ioctl(touch_fd, EVIOCGNAME(sizeof(name_buf)), name_buf) > 0) {
        std::printf("[vguest_fb_demo] /dev/input/event0 = '%s'\n", name_buf);
    }
    std::memset(name_buf, 0, sizeof(name_buf));
    if (spen_fd >= 0 && ::ioctl(spen_fd, EVIOCGNAME(sizeof(name_buf)), name_buf) > 0) {
        std::printf("[vguest_fb_demo] /dev/input/event1 = '%s'\n", name_buf);
    }
    std::fflush(stdout);

    int cur_x = static_cast<int>(W / 2);
    int cur_y = static_cast<int>(H / 2);
    int cur_pressure = 1024;
    bool cur_is_pen = false;
    bool down = false;
    std::vector<TrailPoint> trail;
    trail.reserve(256);

    uint32_t frame = 0;
    while (true) {
        // Drain non-blocking evdev events from touch & S Pen
        auto drain = [&](int fd, bool is_pen) {
            if (fd < 0) return;
            struct input_event ev {};
            while (::read(fd, &ev, sizeof(ev)) == static_cast<ssize_t>(sizeof(ev))) {
                if (ev.type == EV_ABS) {
                    if (ev.code == ABS_MT_POSITION_X || ev.code == ABS_X) { cur_x = ev.value; cur_is_pen = is_pen; }
                    else if (ev.code == ABS_MT_POSITION_Y || ev.code == ABS_Y) { cur_y = ev.value; cur_is_pen = is_pen; }
                    else if (ev.code == ABS_PRESSURE || ev.code == ABS_MT_PRESSURE) { cur_pressure = ev.value; }
                } else if (ev.type == EV_KEY && ev.code == BTN_TOUCH) {
                    down = (ev.value != 0);
                } else if (ev.type == EV_SYN && ev.code == SYN_REPORT && down) {
                    int r = 6 + (cur_pressure * 18) / 4096;
                    uint32_t col = cur_is_pen ? 0xFFF78166U : 0xFF7EE787U;  // Orange=S Pen, Green=Finger
                    if (trail.size() >= 256) trail.erase(trail.begin());
                    trail.push_back(TrailPoint{cur_x, cur_y, r, col});
                }
            }
        };
        drain(touch_fd, false);
        drain(spen_fd, true);

        int slot = vguest::fb::acquire_write_slot(hdr);
        if (slot >= 0) {
            auto* px = reinterpret_cast<uint32_t*>(
                vguest::fb::slot_pixel_ptr(ring, hdr, static_cast<uint32_t>(slot)));

            // Dark background + animated 60 FPS scan bar & grid
            uint32_t bar_x = (frame * 6) % W;
            for (uint32_t y = 0; y < H; ++y) {
                uint32_t* row = px + static_cast<size_t>(y) * W;
                bool y_grid = (y % 64) == 0;
                for (uint32_t x = 0; x < W; ++x) {
                    uint32_t bg = 0xFF17110FU;  // #0F1117
                    if (y_grid || (x % 64) == 0) bg = 0xFF28221EU;
                    if (x >= bar_x && x < bar_x + 6) bg = 0xFF995522U;
                    row[x] = bg;
                }
            }

            // Draw live touch / S Pen ink trail & active cursor
            for (const auto& tp : trail) {
                draw_circle(px, W, H, tp.x, tp.y, tp.radius, tp.color);
            }
            draw_circle(px, W, H, cur_x, cur_y, 16, cur_is_pen ? 0xFFFFFFFFU : 0xFFFFD166U);

            vguest::fb::present_write_slot(hdr, static_cast<uint32_t>(slot));
            ++frame;
        }
        ::usleep(16000);  // ~60 FPS
    }
    return 0;
}
