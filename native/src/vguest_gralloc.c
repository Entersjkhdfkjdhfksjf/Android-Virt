/*
 * VGuest Virtual Gralloc0 HAL (gralloc.virt.so / gralloc.default.so)
 *
 * Pure userspace memfd + mmap graphics buffer allocator & mapper matching
 * AOSP 12 LP64 hardware/hardware.h + hardware/gralloc.h ABI with zero
 * external HIDL or kernel DRM dependencies.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

/* ---- AOSP native_handle.h ABI ---- */
typedef struct native_handle {
    int version; /* sizeof(native_handle_t) */
    int numFds;
    int numInts;
    int data[0];
} native_handle_t;

typedef const native_handle_t* buffer_handle_t;

/* ---- AOSP system/graphics.h YCbCr struct ---- */
struct android_ycbcr {
    void* y;
    void* cb;
    void* cr;
    size_t ystride;
    size_t cstride;
    size_t chroma_step;
    uint32_t reserved[8];
};

/* ---- AOSP hardware/hardware.h ABI (LP64-exact) ---- */
#define MAKE_TAG_CONSTANT(A, B, C, D) \
    (((uint32_t)(A) << 24) | ((uint32_t)(B) << 16) | ((uint32_t)(C) << 8) | (uint32_t)(D))
#define HARDWARE_MODULE_TAG MAKE_TAG_CONSTANT('H', 'W', 'M', 'T')
#define HARDWARE_DEVICE_TAG MAKE_TAG_CONSTANT('H', 'W', 'D', 'T')
#define HARDWARE_MAKE_API_VERSION(maj, min) ((((maj)&0xff) << 8) | ((min)&0xff))
#define HARDWARE_HAL_API_VERSION HARDWARE_MAKE_API_VERSION(1, 0)

struct hw_module_t;
struct hw_module_methods_t;
struct hw_device_t;

typedef struct hw_module_t {
    uint32_t tag;
    uint16_t module_api_version;
    uint16_t hal_api_version;
    const char* id;
    const char* name;
    const char* author;
    struct hw_module_methods_t* methods;
    void* dso;
#ifdef __LP64__
    uint64_t reserved[32 - 7];
#else
    uint32_t reserved[32 - 7];
#endif
} hw_module_t;

typedef struct hw_module_methods_t {
    int (*open)(const struct hw_module_t* module, const char* id, struct hw_device_t** device);
} hw_module_methods_t;

typedef struct hw_device_t {
    uint32_t tag;
    uint32_t version;
    struct hw_module_t* module;
#ifdef __LP64__
    uint64_t reserved[12];
#else
    uint32_t reserved[12];
#endif
    int (*close)(struct hw_device_t* device);
} hw_device_t;

/* ---- AOSP hardware/gralloc.h ABI (GRALLOC_MODULE_API_VERSION_0_3) ---- */
#define GRALLOC_HARDWARE_MODULE_ID "gralloc"
#define GRALLOC_HARDWARE_GPU0 "gpu0"
#define GRALLOC_MODULE_API_VERSION_0_3 HARDWARE_MAKE_API_VERSION(0, 3)
#define GRALLOC_DEVICE_API_VERSION_0_1 HARDWARE_MAKE_API_VERSION(0, 1)

typedef struct gralloc_module_t {
    struct hw_module_t common;
    int (*registerBuffer)(struct gralloc_module_t const* module, buffer_handle_t handle);
    int (*unregisterBuffer)(struct gralloc_module_t const* module, buffer_handle_t handle);
    int (*lock)(struct gralloc_module_t const* module, buffer_handle_t handle, int usage,
                int l, int t, int w, int h, void** vaddr);
    int (*unlock)(struct gralloc_module_t const* module, buffer_handle_t handle);
    int (*perform)(struct gralloc_module_t const* module, int operation, ...);
    int (*lock_ycbcr)(struct gralloc_module_t const* module, buffer_handle_t handle, int usage,
                      int l, int t, int w, int h, struct android_ycbcr* ycbcr);
    int (*lockAsync)(struct gralloc_module_t const* module, buffer_handle_t handle, int usage,
                     int l, int t, int w, int h, void** vaddr, int fenceFd);
    int (*unlockAsync)(struct gralloc_module_t const* module, buffer_handle_t handle, int* fenceFd);
    int (*lockAsync_ycbcr)(struct gralloc_module_t const* module, buffer_handle_t handle, int usage,
                           int l, int t, int w, int h, struct android_ycbcr* ycbcr, int fenceFd);
    void* reserved_proc[3];
} gralloc_module_t;

typedef struct alloc_device_t {
    struct hw_device_t common;
    int (*alloc)(struct alloc_device_t* dev, int w, int h, int format, int usage,
                 buffer_handle_t* handle, int* stride);
    int (*free)(struct alloc_device_t* dev, buffer_handle_t handle);
    void (*dump)(struct alloc_device_t* dev, char* buff, int buff_len);
    void* reserved_proc[7];
} alloc_device_t;

/* ---- Pixel formats (HAL_PIXEL_FORMAT_*) ---- */
#define HAL_PIXEL_FORMAT_RGBA_8888 1
#define HAL_PIXEL_FORMAT_RGBX_8888 2
#define HAL_PIXEL_FORMAT_RGB_888 3
#define HAL_PIXEL_FORMAT_RGB_565 4
#define HAL_PIXEL_FORMAT_BGRA_8888 5
#define HAL_PIXEL_FORMAT_YCrCb_420_SP 17
#define HAL_PIXEL_FORMAT_RGBA_FP16 22
#define HAL_PIXEL_FORMAT_BLOB 33
#define HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED 34
#define HAL_PIXEL_FORMAT_YCbCr_420_888 35
#define HAL_PIXEL_FORMAT_RGBA_1010102 43
#define HAL_PIXEL_FORMAT_YV12 0x32315659

/* ---- VGuest private buffer handle ---- */
#define VGUEST_GRALLOC_MAGIC 0x56475241 /* "VGRA" */
#define VGUEST_NUM_FDS 1
#define VGUEST_NUM_INTS 9

typedef struct vguest_buffer_handle {
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
} vguest_buffer_handle_t;

/* ---- Per-process mmap tracking table ---- */
#define MAX_MAPPED_BUFFERS 512

typedef struct mapped_entry {
    const native_handle_t* handle;
    int fd;
    void* base;
    size_t size;
    int refcount;
} mapped_entry_t;

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static mapped_entry_t g_mappings[MAX_MAPPED_BUFFERS];

static int validate_handle(buffer_handle_t hnd) {
    if (!hnd) return -EINVAL;
    if (hnd->version != (int)sizeof(native_handle_t)) return -EINVAL;
    if (hnd->numFds != VGUEST_NUM_FDS || hnd->numInts != VGUEST_NUM_INTS) return -EINVAL;
    const vguest_buffer_handle_t* vh = (const vguest_buffer_handle_t*)hnd;
    if (vh->magic != VGUEST_GRALLOC_MAGIC || vh->fd < 0 || vh->size <= 0) return -EINVAL;
    return 0;
}

static mapped_entry_t* find_mapping_locked(buffer_handle_t hnd, int fd) {
    for (int i = 0; i < MAX_MAPPED_BUFFERS; ++i) {
        if (g_mappings[i].base != NULL &&
            (g_mappings[i].handle == hnd || g_mappings[i].fd == fd)) {
            return &g_mappings[i];
        }
    }
    return NULL;
}

static int map_buffer_locked(const vguest_buffer_handle_t* vh, void** out_base) {
    mapped_entry_t* e = find_mapping_locked(&vh->base, vh->fd);
    if (e) {
        e->refcount++;
        if (out_base) *out_base = e->base;
        return 0;
    }

    int slot = -1;
    for (int i = 0; i < MAX_MAPPED_BUFFERS; ++i) {
        if (g_mappings[i].base == NULL) {
            slot = i;
            break;
        }
    }
    if (slot < 0) return -ENOMEM;

    void* ptr = mmap(NULL, (size_t)vh->size, PROT_READ | PROT_WRITE, MAP_SHARED, vh->fd, 0);
    if (ptr == MAP_FAILED) {
        return -errno;
    }

    g_mappings[slot].handle = &vh->base;
    g_mappings[slot].fd = vh->fd;
    g_mappings[slot].base = ptr;
    g_mappings[slot].size = (size_t)vh->size;
    g_mappings[slot].refcount = 1;
    if (out_base) *out_base = ptr;
    return 0;
}

static int create_backing_fd(size_t size) {
    int fd = -1;
#ifdef __NR_memfd_create
    fd = (int)syscall(__NR_memfd_create, "vguest_gralloc", 1U /* MFD_CLOEXEC */);
#endif
    if (fd < 0) {
        char tmpl[] = "/data/local/tmp/vgralloc_XXXXXX";
        fd = mkstemp(tmpl);
        if (fd >= 0) {
            unlink(tmpl);
            fcntl(fd, F_SETFD, FD_CLOEXEC);
        }
    }
    if (fd < 0) return -errno;
    if (ftruncate(fd, (off_t)size) != 0) {
        int err = -errno;
        close(fd);
        return err;
    }
    return fd;
}

static size_t align_up(size_t v, size_t a) {
    return (v + a - 1) & ~(a - 1);
}

static void compute_format_layout(int w, int h, int format, int* out_stride, int* out_bpp,
                                  size_t* out_size) {
    int bpp = 4;
    size_t stride = 0;
    size_t total = 0;

    switch (format) {
        case HAL_PIXEL_FORMAT_RGB_565:
            bpp = 2;
            stride = align_up((size_t)w, 8);
            total = stride * (size_t)h * 2;
            break;
        case HAL_PIXEL_FORMAT_RGB_888:
            bpp = 3;
            stride = align_up((size_t)w, 8);
            total = stride * (size_t)h * 3;
            break;
        case HAL_PIXEL_FORMAT_RGBA_FP16:
            bpp = 8;
            stride = align_up((size_t)w, 8);
            total = stride * (size_t)h * 8;
            break;
        case HAL_PIXEL_FORMAT_BLOB:
            bpp = 1;
            stride = (size_t)w;
            total = (size_t)w * (size_t)(h > 0 ? h : 1);
            break;
        case HAL_PIXEL_FORMAT_YV12:
        case HAL_PIXEL_FORMAT_YCbCr_420_888:
        case HAL_PIXEL_FORMAT_YCrCb_420_SP: {
            bpp = 1;
            stride = align_up((size_t)w, 16);
            size_t c_stride = align_up(stride / 2, 16);
            size_t y_size = stride * (size_t)h;
            size_t c_size = c_stride * (size_t)((h + 1) / 2);
            total = y_size + 2 * c_size;
            break;
        }
        case HAL_PIXEL_FORMAT_RGBA_8888:
        case HAL_PIXEL_FORMAT_RGBX_8888:
        case HAL_PIXEL_FORMAT_BGRA_8888:
        case HAL_PIXEL_FORMAT_RGBA_1010102:
        case HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED:
        default:
            bpp = 4;
            stride = align_up((size_t)w, 8);
            total = stride * (size_t)h * 4;
            break;
    }

    if (total == 0) total = 4096;
    *out_stride = (int)stride;
    *out_bpp = bpp;
    *out_size = align_up(total, 4096);
}

/* ---- gralloc_module_t callbacks ---- */

static int vguest_register_buffer(struct gralloc_module_t const* module, buffer_handle_t handle) {
    (void)module;
    if (validate_handle(handle) != 0) return -EINVAL;
    const vguest_buffer_handle_t* vh = (const vguest_buffer_handle_t*)handle;
    pthread_mutex_lock(&g_lock);
    int rc = map_buffer_locked(vh, NULL);
    pthread_mutex_unlock(&g_lock);
    return rc;
}

static int vguest_unregister_buffer(struct gralloc_module_t const* module, buffer_handle_t handle) {
    (void)module;
    if (validate_handle(handle) != 0) return -EINVAL;
    const vguest_buffer_handle_t* vh = (const vguest_buffer_handle_t*)handle;
    pthread_mutex_lock(&g_lock);
    mapped_entry_t* e = find_mapping_locked(handle, vh->fd);
    if (e) {
        e->refcount--;
        if (e->refcount <= 0) {
            munmap(e->base, e->size);
            memset(e, 0, sizeof(*e));
        }
    }
    pthread_mutex_unlock(&g_lock);
    return 0;
}

static int vguest_lock(struct gralloc_module_t const* module, buffer_handle_t handle, int usage,
                       int l, int t, int w, int h, void** vaddr) {
    (void)module;
    (void)usage;
    (void)l;
    (void)t;
    (void)w;
    (void)h;
    if (validate_handle(handle) != 0) return -EINVAL;
    const vguest_buffer_handle_t* vh = (const vguest_buffer_handle_t*)handle;

    pthread_mutex_lock(&g_lock);
    mapped_entry_t* e = find_mapping_locked(handle, vh->fd);
    void* base = NULL;
    int rc = 0;
    if (e) {
        base = e->base;
    } else {
        rc = map_buffer_locked(vh, &base);
    }
    pthread_mutex_unlock(&g_lock);

    if (rc != 0) return rc;
    if (vaddr) *vaddr = base;
    return 0;
}

static int vguest_unlock(struct gralloc_module_t const* module, buffer_handle_t handle) {
    (void)module;
    if (validate_handle(handle) != 0) return -EINVAL;
    return 0;
}

static int vguest_perform(struct gralloc_module_t const* module, int operation, ...) {
    (void)module;
    (void)operation;
    return -EINVAL;
}

static int vguest_lock_ycbcr(struct gralloc_module_t const* module, buffer_handle_t handle,
                             int usage, int l, int t, int w, int h, struct android_ycbcr* ycbcr) {
    if (!ycbcr) return -EINVAL;
    void* base = NULL;
    int rc = vguest_lock(module, handle, usage, l, t, w, h, &base);
    if (rc != 0) return rc;

    const vguest_buffer_handle_t* vh = (const vguest_buffer_handle_t*)handle;
    uint8_t* ptr = (uint8_t*)base;
    size_t ystride = (size_t)vh->stride;
    size_t cstride = align_up(ystride / 2, 16);
    size_t y_size = ystride * (size_t)vh->height;
    size_t c_size = cstride * (size_t)((vh->height + 1) / 2);

    memset(ycbcr, 0, sizeof(*ycbcr));
    ycbcr->y = ptr;
    ycbcr->ystride = ystride;
    if (vh->format == HAL_PIXEL_FORMAT_YV12) {
        ycbcr->cr = ptr + y_size;
        ycbcr->cb = ptr + y_size + c_size;
        ycbcr->cstride = cstride;
        ycbcr->chroma_step = 1;
    } else {
        ycbcr->cb = ptr + y_size;
        ycbcr->cr = ptr + y_size + c_size;
        ycbcr->cstride = cstride;
        ycbcr->chroma_step = 1;
    }
    return 0;
}

static int vguest_lock_async(struct gralloc_module_t const* module, buffer_handle_t handle,
                             int usage, int l, int t, int w, int h, void** vaddr, int fenceFd) {
    if (fenceFd >= 0) close(fenceFd);
    return vguest_lock(module, handle, usage, l, t, w, h, vaddr);
}

static int vguest_unlock_async(struct gralloc_module_t const* module, buffer_handle_t handle,
                               int* fenceFd) {
    if (fenceFd) *fenceFd = -1;
    return vguest_unlock(module, handle);
}

static int vguest_lock_async_ycbcr(struct gralloc_module_t const* module, buffer_handle_t handle,
                                   int usage, int l, int t, int w, int h,
                                   struct android_ycbcr* ycbcr, int fenceFd) {
    if (fenceFd >= 0) close(fenceFd);
    return vguest_lock_ycbcr(module, handle, usage, l, t, w, h, ycbcr);
}

/* ---- alloc_device_t callbacks ---- */

static int vguest_alloc(struct alloc_device_t* dev, int w, int h, int format, int usage,
                        buffer_handle_t* handle, int* stride) {
    (void)dev;
    if (!handle || !stride || w <= 0 || h <= 0) return -EINVAL;

    int calc_stride = 0;
    int bpp = 4;
    size_t size = 0;
    compute_format_layout(w, h, format, &calc_stride, &bpp, &size);

    int fd = create_backing_fd(size);
    if (fd < 0) return fd;

    vguest_buffer_handle_t* vh = (vguest_buffer_handle_t*)calloc(1, sizeof(vguest_buffer_handle_t));
    if (!vh) {
        close(fd);
        return -ENOMEM;
    }

    vh->base.version = (int)sizeof(native_handle_t);
    vh->base.numFds = VGUEST_NUM_FDS;
    vh->base.numInts = VGUEST_NUM_INTS;
    vh->fd = fd;
    vh->magic = VGUEST_GRALLOC_MAGIC;
    vh->size = (int)size;
    vh->width = w;
    vh->height = h;
    vh->stride = calc_stride;
    vh->format = format;
    vh->bpp = bpp;
    vh->usage = usage;
    vh->flags = 0;

    pthread_mutex_lock(&g_lock);
    int rc = map_buffer_locked(vh, NULL);
    pthread_mutex_unlock(&g_lock);
    if (rc != 0) {
        close(fd);
        free(vh);
        return rc;
    }

    *handle = &vh->base;
    *stride = calc_stride;
    return 0;
}

static int vguest_free(struct alloc_device_t* dev, buffer_handle_t handle) {
    (void)dev;
    if (validate_handle(handle) != 0) return -EINVAL;
    vguest_buffer_handle_t* vh = (vguest_buffer_handle_t*)handle;

    pthread_mutex_lock(&g_lock);
    mapped_entry_t* e = find_mapping_locked(handle, vh->fd);
    if (e) {
        munmap(e->base, e->size);
        memset(e, 0, sizeof(*e));
    }
    pthread_mutex_unlock(&g_lock);

    if (vh->fd >= 0) close(vh->fd);
    vh->magic = 0;
    free(vh);
    return 0;
}

static int vguest_alloc_close(struct hw_device_t* device) {
    free(device);
    return 0;
}

static int vguest_gralloc_open(const struct hw_module_t* module, const char* id,
                               struct hw_device_t** device) {
    if (!device || !id) return -EINVAL;
    if (strcmp(id, GRALLOC_HARDWARE_GPU0) != 0) return -EINVAL;

    alloc_device_t* dev = (alloc_device_t*)calloc(1, sizeof(alloc_device_t));
    if (!dev) return -ENOMEM;

    dev->common.tag = HARDWARE_DEVICE_TAG;
    dev->common.version = GRALLOC_DEVICE_API_VERSION_0_1;
    dev->common.module = (struct hw_module_t*)module;
    dev->common.close = vguest_alloc_close;
    dev->alloc = vguest_alloc;
    dev->free = vguest_free;
    dev->dump = NULL;

    *device = &dev->common;
    return 0;
}

static struct hw_module_methods_t g_gralloc_methods = {
    .open = vguest_gralloc_open,
};

__attribute__((visibility("default")))
gralloc_module_t HMI = {
    .common = {
        .tag = HARDWARE_MODULE_TAG,
        .module_api_version = GRALLOC_MODULE_API_VERSION_0_3,
        .hal_api_version = HARDWARE_HAL_API_VERSION,
        .id = GRALLOC_HARDWARE_MODULE_ID,
        .name = "VGuest Virtual Gralloc0 HAL",
        .author = "VGuest",
        .methods = &g_gralloc_methods,
        .dso = NULL,
        .reserved = {0},
    },
    .registerBuffer = vguest_register_buffer,
    .unregisterBuffer = vguest_unregister_buffer,
    .lock = vguest_lock,
    .unlock = vguest_unlock,
    .perform = vguest_perform,
    .lock_ycbcr = vguest_lock_ycbcr,
    .lockAsync = vguest_lock_async,
    .unlockAsync = vguest_unlock_async,
    .lockAsync_ycbcr = vguest_lock_async_ycbcr,
    .reserved_proc = {0},
};
