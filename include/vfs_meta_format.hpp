#pragma once

#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <optional>
#include <string_view>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

namespace vguest {

static constexpr char kVmdbMagic[4] = {'V', 'M', 'D', 'B'};
static constexpr uint32_t kVmdbVersion = 1;

static constexpr uint32_t kVmdbFlagIsDevNode = 1u << 0;
static constexpr uint32_t kVmdbFlagHasCaps   = 1u << 1;
static constexpr uint32_t kVmdbFlagFromApex  = 1u << 2;

#pragma pack(push, 1)
struct VfsMetaHeader {
    char magic[4];            // "VMDB"
    uint32_t version;         // 1
    uint32_t entry_size;      // 48
    uint32_t reserved;        // 0
    uint32_t entry_count;     // Sorted by (path_hash, path)
    uint64_t entry_table_off; // 64
    uint64_t string_table_off;
    uint64_t total_size;
    uint8_t padding[20];
};

struct VfsMetaEntry {
    uint64_t path_hash;   // 64-bit FNV-1a of canonical guest path
    uint32_t path_off;    // Offset into string table (NUL-terminated)
    uint16_t path_len;    // Byte length of guest path
    uint16_t selinux_len; // Byte length of SELinux context
    uint32_t selinux_off; // Offset into string table (NUL-terminated)
    uint32_t uid;
    uint32_t gid;
    uint32_t mode;        // Full POSIX st_mode (type + perms + suid/sgid)
    uint32_t rdev;        // Virtualized major/minor for char/block devices
    uint32_t caps_lo;     // Permitted capabilities bits [0..31]
    uint32_t caps_hi;     // Permitted capabilities bits [32..63]
    uint32_t flags;       // kVmdbFlag*
};
#pragma pack(pop)

static_assert(sizeof(VfsMetaHeader) == 64, "VfsMetaHeader must be 64 bytes");
static_assert(sizeof(VfsMetaEntry) == 48, "VfsMetaEntry must be 48 bytes");

inline uint64_t fnv1a_64(std::string_view s) noexcept {
    uint64_t h = 0xCBF29CE484222325ULL;
    for (unsigned char c : s) {
        h ^= static_cast<uint64_t>(c);
        h *= 0x100000001B3ULL;
    }
    return h;
}

struct VfsMetaView {
    const VfsMetaEntry* entry;
    std::string_view path;
    std::string_view selinux;
};

// Zero-copy mmap reader for rootfs_meta.db used by Phase 2 guest_runner.
class VfsMetaDb {
public:
    VfsMetaDb() = default;
    ~VfsMetaDb() { close(); }

    VfsMetaDb(const VfsMetaDb&) = delete;
    VfsMetaDb& operator=(const VfsMetaDb&) = delete;

    bool open(const char* db_path) noexcept {
        close();
        int fd = ::open(db_path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) return false;

        struct stat st {};
        if (::fstat(fd, &st) != 0 || st.st_size < static_cast<off_t>(sizeof(VfsMetaHeader))) {
            ::close(fd);
            return false;
        }

        void* map = ::mmap(nullptr, static_cast<size_t>(st.st_size), PROT_READ, MAP_PRIVATE, fd, 0);
        ::close(fd);
        if (map == MAP_FAILED) return false;

        const auto* hdr = reinterpret_cast<const VfsMetaHeader*>(map);
        if (std::memcmp(hdr->magic, kVmdbMagic, 4) != 0 ||
            hdr->version != kVmdbVersion ||
            hdr->entry_size != sizeof(VfsMetaEntry) ||
            hdr->total_size != static_cast<uint64_t>(st.st_size)) {
            ::munmap(map, static_cast<size_t>(st.st_size));
            return false;
        }

        base_ = reinterpret_cast<const uint8_t*>(map);
        size_ = static_cast<size_t>(st.st_size);
        header_ = hdr;
        entries_ = reinterpret_cast<const VfsMetaEntry*>(base_ + hdr->entry_table_off);
        strings_ = reinterpret_cast<const char*>(base_ + hdr->string_table_off);
        return true;
    }

    void close() noexcept {
        if (base_) {
            ::munmap(const_cast<uint8_t*>(base_), size_);
            base_ = nullptr;
            size_ = 0;
            header_ = nullptr;
            entries_ = nullptr;
            strings_ = nullptr;
        }
    }

    uint32_t count() const noexcept { return header_ ? header_->entry_count : 0; }

    // O(log N) binary search by FNV-1a hash with exact string verification.
    std::optional<VfsMetaView> find(std::string_view guest_path) const noexcept {
        if (!header_ || header_->entry_count == 0) return std::nullopt;
        const uint64_t target_hash = fnv1a_64(guest_path);

        uint32_t lo = 0;
        uint32_t hi = header_->entry_count;
        while (lo < hi) {
            uint32_t mid = lo + ((hi - lo) >> 1);
            if (entries_[mid].path_hash < target_hash) {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }

        for (uint32_t i = lo; i < header_->entry_count && entries_[i].path_hash == target_hash; ++i) {
            const VfsMetaEntry& e = entries_[i];
            std::string_view p(strings_ + e.path_off, e.path_len);
            if (p == guest_path) {
                std::string_view s(strings_ + e.selinux_off, e.selinux_len);
                return VfsMetaView{&e, p, s};
            }
        }
        return std::nullopt;
    }

private:
    const uint8_t* base_ = nullptr;
    size_t size_ = 0;
    const VfsMetaHeader* header_ = nullptr;
    const VfsMetaEntry* entries_ = nullptr;
    const char* strings_ = nullptr;
};

}  // namespace vguest
