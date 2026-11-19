#pragma once

#include <cstdint>
#include <sys/ioctl.h>

namespace vguest::binder {

// Exact 64-bit Linux/Android 12 Binder UAPI (arm64-v8a / x86_64)
using binder_size_t = uint64_t;
using binder_uintptr_t = uint64_t;

constexpr int32_t kBinderCurrentProtocolVersion = 8;

constexpr uint32_t pack_chars(uint8_t c1, uint8_t c2, uint8_t c3, uint8_t c4) {
    return (static_cast<uint32_t>(c1) << 24) |
           (static_cast<uint32_t>(c2) << 16) |
           (static_cast<uint32_t>(c3) << 8)  |
           static_cast<uint32_t>(c4);
}

enum BinderObjectType : uint32_t {
    kBinderTypeBinder     = pack_chars('s', 'b', '*', 0x85),
    kBinderTypeWeakBinder = pack_chars('w', 'b', '*', 0x85),
    kBinderTypeHandle     = pack_chars('s', 'h', '*', 0x85),
    kBinderTypeWeakHandle = pack_chars('w', 'h', '*', 0x85),
    kBinderTypeFd         = pack_chars('f', 'd', '*', 0x85),
    kBinderTypeFda        = pack_chars('f', 'd', 'a', 0x85),
    kBinderTypePtr        = pack_chars('p', 't', '*', 0x85),
};

enum TransactionFlags : uint32_t {
    kTfOneWay     = 0x01,
    kTfRootObject = 0x04,
    kTfStatusCode = 0x08,
    kTfAcceptFds  = 0x10,
};

struct binder_object_header {
    uint32_t type;
};

struct flat_binder_object {
    struct binder_object_header hdr;
    uint32_t flags;
    union {
        binder_uintptr_t binder;
        uint32_t handle;
    };
    binder_uintptr_t cookie;
};

struct binder_fd_object {
    struct binder_object_header hdr;
    uint32_t pad_flags;
    union {
        binder_uintptr_t pad_binder;
        uint32_t fd;
    };
    binder_uintptr_t cookie;
};

struct binder_buffer_object {
    struct binder_object_header hdr;
    uint32_t flags;
    binder_uintptr_t buffer;
    binder_size_t length;
    binder_size_t parent;
    binder_size_t parent_offset;
};

struct binder_write_read {
    binder_size_t write_size;
    binder_size_t write_consumed;
    binder_uintptr_t write_buffer;
    binder_size_t read_size;
    binder_size_t read_consumed;
    binder_uintptr_t read_buffer;
};

struct binder_version {
    int32_t protocol_version;
};

struct binder_transaction_data {
    union {
        uint32_t handle;
        binder_uintptr_t ptr;
    } target;
    binder_uintptr_t cookie;
    uint32_t code;
    uint32_t flags;
    int32_t sender_pid;
    uint32_t sender_euid;
    binder_size_t data_size;
    binder_size_t offsets_size;
    union {
        struct {
            binder_uintptr_t buffer;
            binder_uintptr_t offsets;
        } ptr;
        uint8_t buf[8];
    } data;
};

struct binder_transaction_data_sg {
    struct binder_transaction_data transaction_data;
    binder_size_t buffers_size;
};

struct binder_ptr_cookie {
    binder_uintptr_t ptr;
    binder_uintptr_t cookie;
};

struct binder_handle_cookie {
    uint32_t handle;
    binder_uintptr_t cookie;
} __attribute__((packed));

// Binder ioctls ('b' = 0x62)
constexpr unsigned long kIoctlBinderWriteRead         = _IOWR('b', 1, struct binder_write_read);
constexpr unsigned long kIoctlBinderSetIdleTimeout    = _IOW('b', 3, int64_t);
constexpr unsigned long kIoctlBinderSetMaxThreads     = _IOW('b', 5, uint32_t);
constexpr unsigned long kIoctlBinderSetIdlePriority   = _IOW('b', 6, int32_t);
constexpr unsigned long kIoctlBinderSetContextMgr     = _IOW('b', 7, int32_t);
constexpr unsigned long kIoctlBinderThreadExit        = _IOW('b', 8, int32_t);
constexpr unsigned long kIoctlBinderVersion           = _IOWR('b', 9, struct binder_version);
constexpr unsigned long kIoctlBinderSetContextMgrExt  = _IOW('b', 13, struct flat_binder_object);

// Driver commands (BC_*)
constexpr uint32_t kBcTransaction             = _IOW('c', 0, struct binder_transaction_data);
constexpr uint32_t kBcReply                   = _IOW('c', 1, struct binder_transaction_data);
constexpr uint32_t kBcAcquireResult           = _IOW('c', 2, int32_t);
constexpr uint32_t kBcFreeBuffer              = _IOW('c', 3, binder_uintptr_t);
constexpr uint32_t kBcIncrefs                 = _IOW('c', 4, uint32_t);
constexpr uint32_t kBcAcquire                 = _IOW('c', 5, uint32_t);
constexpr uint32_t kBcRelease                 = _IOW('c', 6, uint32_t);
constexpr uint32_t kBcDecrefs                 = _IOW('c', 7, uint32_t);
constexpr uint32_t kBcIncrefsDone             = _IOW('c', 8, struct binder_ptr_cookie);
constexpr uint32_t kBcAcquireDone             = _IOW('c', 9, struct binder_ptr_cookie);
constexpr uint32_t kBcRegisterLooper          = _IO('c', 11);
constexpr uint32_t kBcEnterLooper             = _IO('c', 12);
constexpr uint32_t kBcExitLooper              = _IO('c', 13);
constexpr uint32_t kBcRequestDeathNotif       = _IOW('c', 14, struct binder_handle_cookie);
constexpr uint32_t kBcClearDeathNotif         = _IOW('c', 15, struct binder_handle_cookie);
constexpr uint32_t kBcDeadBinderDone          = _IOW('c', 16, binder_uintptr_t);
constexpr uint32_t kBcTransactionSg           = _IOW('c', 17, struct binder_transaction_data_sg);
constexpr uint32_t kBcReplySg                 = _IOW('c', 18, struct binder_transaction_data_sg);

// Driver return codes (BR_*)
constexpr uint32_t kBrError                   = _IOR('r', 0, int32_t);
constexpr uint32_t kBrOk                      = _IO('r', 1);
constexpr uint32_t kBrTransaction             = _IOR('r', 2, struct binder_transaction_data);
constexpr uint32_t kBrReply                   = _IOR('r', 3, struct binder_transaction_data);
constexpr uint32_t kBrDeadReply               = _IO('r', 5);
constexpr uint32_t kBrTransactionComplete     = _IO('r', 6);
constexpr uint32_t kBrIncrefs                 = _IOR('r', 7, struct binder_ptr_cookie);
constexpr uint32_t kBrAcquire                 = _IOR('r', 8, struct binder_ptr_cookie);
constexpr uint32_t kBrRelease                 = _IOR('r', 9, struct binder_ptr_cookie);
constexpr uint32_t kBrDecrefs                 = _IOR('r', 10, struct binder_ptr_cookie);
constexpr uint32_t kBrNoop                    = _IO('r', 12);
constexpr uint32_t kBrSpawnLooper             = _IO('r', 13);
constexpr uint32_t kBrDeadBinder              = _IOR('r', 15, binder_uintptr_t);
constexpr uint32_t kBrClearDeathNotifDone     = _IOR('r', 16, binder_uintptr_t);
constexpr uint32_t kBrFailedReply             = _IO('r', 17);

static_assert(sizeof(binder_write_read) == 48, "64-bit binder_write_read must be 48 bytes");
static_assert(sizeof(binder_transaction_data) == 64, "64-bit binder_transaction_data must be 64 bytes");
static_assert(sizeof(flat_binder_object) == 24, "64-bit flat_binder_object must be 24 bytes");

}  // namespace vguest::binder
