#pragma once

#include <atomic>
#include <cstdint>
#include <cstring>

namespace vguest::fb {

static constexpr char kFbMagic[4] = {'V', 'G', 'F', 'B'};
static constexpr uint32_t kFbVersion = 1;
static constexpr uint32_t kFbNumSlots = 3;
static constexpr size_t kFbHeaderSize = 4096;  // 1 page aligned

enum SlotState : uint32_t {
    kSlotFree       = 0,
    kSlotWriting    = 1,
    kSlotReady      = 2,
    kSlotDisplaying = 3,
};

// 4096-byte shared-memory control page at offset 0 of .vguest_fb_ring
struct VirtFbHeader {
    char magic[4];                      // "VGFB"
    uint32_t version;                   // 1
    uint32_t width;                     // e.g. 1400 (1/2 native Tab S7+ 2800x1752)
    uint32_t height;                    // e.g. 876
    uint32_t stride_bytes;              // width * 4 (RGBA_8888)
    uint32_t slot_bytes;                // page-aligned size of each frame slot
    uint32_t num_slots;                 // 3
    uint32_t reserved0;
    std::atomic<uint32_t> frame_seq;    // Monotonic frame counter
    std::atomic<uint32_t> latest_ready; // Most recently presented slot index [0..2]
    std::atomic<uint32_t> vsync_seq;    // Host Choreographer VSYNC counter
    std::atomic<uint32_t> slot_state[kFbNumSlots];
};

static_assert(sizeof(VirtFbHeader) <= kFbHeaderSize, "VirtFbHeader must fit in 4096 bytes");

inline uint32_t align_page(uint32_t v) noexcept {
    return (v + 4095u) & ~4095u;
}

inline size_t compute_ring_total_size(uint32_t width, uint32_t height) noexcept {
    uint32_t slot_bytes = align_page(width * height * 4u);
    return kFbHeaderSize + static_cast<size_t>(slot_bytes) * kFbNumSlots;
}

inline void init_fb_header(VirtFbHeader* hdr, uint32_t width, uint32_t height) noexcept {
    std::memset(hdr, 0, kFbHeaderSize);
    std::memcpy(hdr->magic, kFbMagic, 4);
    hdr->version = kFbVersion;
    hdr->width = width;
    hdr->height = height;
    hdr->stride_bytes = width * 4u;
    hdr->slot_bytes = align_page(hdr->stride_bytes * height);
    hdr->num_slots = kFbNumSlots;
    hdr->frame_seq.store(0, std::memory_order_relaxed);
    hdr->latest_ready.store(0, std::memory_order_relaxed);
    hdr->vsync_seq.store(0, std::memory_order_relaxed);
    for (uint32_t i = 0; i < kFbNumSlots; ++i) {
        hdr->slot_state[i].store(kSlotFree, std::memory_order_relaxed);
    }
}

inline uint8_t* slot_pixel_ptr(uint8_t* ring_base, const VirtFbHeader* hdr, uint32_t slot) noexcept {
    return ring_base + kFbHeaderSize + static_cast<size_t>(slot) * hdr->slot_bytes;
}

// Producer: acquire a FREE (or oldest READY if consumer is slow) slot for writing.
inline int acquire_write_slot(VirtFbHeader* hdr) noexcept {
    for (uint32_t i = 0; i < kFbNumSlots; ++i) {
        uint32_t expected = kSlotFree;
        if (hdr->slot_state[i].compare_exchange_strong(
                expected, kSlotWriting, std::memory_order_acq_rel)) {
            return static_cast<int>(i);
        }
    }
    // Triple-buffer overwrite policy: reclaim a non-displaying READY slot so producer never stalls
    for (uint32_t i = 0; i < kFbNumSlots; ++i) {
        uint32_t expected = kSlotReady;
        if (hdr->slot_state[i].compare_exchange_strong(
                expected, kSlotWriting, std::memory_order_acq_rel)) {
            return static_cast<int>(i);
        }
    }
    return -1;
}

// Producer: publish completed frame slot.
inline void present_write_slot(VirtFbHeader* hdr, uint32_t slot) noexcept {
    hdr->slot_state[slot].store(kSlotReady, std::memory_order_release);
    hdr->latest_ready.store(slot, std::memory_order_release);
    hdr->frame_seq.fetch_add(1, std::memory_order_release);
}

// Consumer: acquire the latest READY slot for ANativeWindow presentation.
inline int acquire_ready_slot(VirtFbHeader* hdr) noexcept {
    uint32_t cand = hdr->latest_ready.load(std::memory_order_acquire) % kFbNumSlots;
    uint32_t expected = kSlotReady;
    if (hdr->slot_state[cand].compare_exchange_strong(
            expected, kSlotDisplaying, std::memory_order_acq_rel)) {
        return static_cast<int>(cand);
    }
    for (uint32_t i = 0; i < kFbNumSlots; ++i) {
        expected = kSlotReady;
        if (hdr->slot_state[i].compare_exchange_strong(
                expected, kSlotDisplaying, std::memory_order_acq_rel)) {
            return static_cast<int>(i);
        }
    }
    return -1;
}

// Consumer: return displayed slot back to FREE.
inline void release_display_slot(VirtFbHeader* hdr, uint32_t slot) noexcept {
    hdr->slot_state[slot].store(kSlotFree, std::memory_order_release);
}

}  // namespace vguest::fb
