#!/usr/bin/env bash
set -euo pipefail

# Cross-compiles AOSP 12 Graphics HALs (arm64-v8a) on GitHub Actions (ubuntu-latest):
#   1. libvguest_hwcomposer.so      -> /vendor/lib64/hw/hwcomposer.{virt,default}.so
#   2. libvguest_mapper20_impl.so   -> /vendor/lib64/hw/android.hardware.graphics.mapper@2.0-impl.so
#   3. libvguest_allocator20_svc.so -> /vendor/bin/hw/android.hardware.graphics.allocator@2.0-service
#   4. libvguest_composer21_svc.so  -> /vendor/bin/hw/android.hardware.graphics.composer@2.1-service

REPO_ROOT="$(pwd)"
WORK="${REPO_ROOT}/hal-build"
OUT="${REPO_ROOT}/graphics-hals-out"
mkdir -p "${WORK}" "${OUT}"

NDK_PATH="${ANDROID_NDK_LATEST_HOME:-${ANDROID_NDK_HOME:-}}"
if [ -z "${NDK_PATH}" ] || [ ! -d "${NDK_PATH}" ]; then
  NDK_PATH="$(ls -d /usr/local/lib/android/sdk/ndk/* 2>/dev/null | sort -V | tail -n 1)"
fi
TOOLCHAIN="${NDK_PATH}/toolchains/llvm/prebuilt/linux-x86_64/bin"
CXX_ARM64="${TOOLCHAIN}/aarch64-linux-android31-clang++"
CC_ARM64="${TOOLCHAIN}/aarch64-linux-android31-clang"
STRIP="${TOOLCHAIN}/llvm-strip"
READELF="${TOOLCHAIN}/llvm-readelf"

echo "=== [1/5] Installing host build deps (bison, flex, libssl-dev, libjsoncpp-dev) ==="
sudo apt-get update -qq
sudo apt-get install -y -qq bison flex libssl-dev libjsoncpp-dev

echo "=== [2/5] Cloning AOSP android-12.1.0_r27 HIDL & Graphics HAL repos ==="
cd "${WORK}"
TAG="android-12.1.0_r27"

clone_sparse() {
  local url="$1" dir="$2"; shift 2
  if [ ! -d "${dir}" ]; then
    git clone --branch "${TAG}" --depth 1 --filter=blob:none --sparse "${url}" "${dir}"
    git -C "${dir}" sparse-checkout set "$@"
  fi
}

[ -d hidl-tools ] || git clone --branch "${TAG}" --depth 1 https://android.googlesource.com/platform/system/tools/hidl hidl-tools
[ -d libbase ]    || git clone --branch "${TAG}" --depth 1 https://android.googlesource.com/platform/system/libbase libbase
[ -d logging ]    || git clone --branch "${TAG}" --depth 1 https://android.googlesource.com/platform/system/logging logging
[ -d libhardware ]|| git clone --branch "${TAG}" --depth 1 https://android.googlesource.com/platform/hardware/libhardware libhardware
[ -d libfmq ]     || git clone --branch "${TAG}" --depth 1 https://android.googlesource.com/platform/system/libfmq libfmq
[ -d libhidl ]    || git clone --branch "${TAG}" --depth 1 https://android.googlesource.com/platform/system/libhidl libhidl
[ -d libhwbinder ]|| git clone --branch "${TAG}" --depth 1 https://android.googlesource.com/platform/system/libhwbinder libhwbinder
clone_sparse https://android.googlesource.com/platform/system/core core libcutils libutils libsystem libsync include
clone_sparse https://android.googlesource.com/platform/frameworks/native native libs/nativewindow libs/nativebase libs/arect libs/ui libs/gralloc libs/binder include
clone_sparse https://android.googlesource.com/platform/hardware/interfaces hw-if graphics/common graphics/allocator/2.0 graphics/mapper graphics/composer/2.1
clone_sparse https://android.googlesource.com/platform/system/hardware/interfaces sys-hw-if suspend/1.0

echo "=== [3/5] Building host hidl-gen ==="
mkdir -p "${WORK}/hidl-gen-build"
cd "${WORK}/hidl-gen-build"

cat > host_compat.h <<'EOF'
#pragma once
#include <cstdint>
#include <cstring>
#include <algorithm>
EOF

cat > host_log_stub.cpp <<'EOF'
#include <cstdarg>
#include <cstdio>
extern "C" int __android_log_buf_print(int, int, const char* tag, const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    if (tag) std::fprintf(stderr, "[%s] ", tag);
    int r = std::vfprintf(stderr, fmt, ap);
    std::fputc('\n', stderr);
    va_end(ap);
    return r;
}
EOF

bison -d -o hidl-gen_y.cpp --defines=hidl-gen_y.h "${WORK}/hidl-tools/hidl-gen_y.yy"
if grep -q "semantic_type" hidl-gen_y.h; then
  cat >> hidl-gen_y.h <<'EOF'
#ifndef VGUEST_BISON_YYSTYPE_ALIAS
#define VGUEST_BISON_YYSTYPE_ALIAS
using YYSTYPE = yy::parser::semantic_type;
using YYLTYPE = yy::parser::location_type;
#endif
EOF
fi
cp hidl-gen_y.h hidl-gen_y.hh
# Let hidl-gen_l.ll include AST.h first, then hidl-gen_y.h (which now defines YYSTYPE/YYLTYPE)
flex -o hidl-gen_l.cpp --header-file=hidl-gen_l.h "${WORK}/hidl-tools/hidl-gen_l.ll"

# Collect only POSIX libbase sources needed on Ubuntu host
LIBBASE_SRCS=""
for f in file.cpp logging.cpp mapped_file.cpp parsebool.cpp parsenetaddress.cpp \
         posix_strerror_r.cpp stringprintf.cpp strings.cpp threads.cpp \
         errors_unix.cpp chrono_utils.cpp hex.cpp; do
  if [ -f "${WORK}/libbase/${f}" ]; then
    LIBBASE_SRCS="${LIBBASE_SRCS} ${WORK}/libbase/${f}"
  fi
done

# Collect only hidl-gen core + utils + host_utils + hashing
HIDL_SRCS=$(find \
  "${WORK}/hidl-tools" \
  -maxdepth 1 -name '*.cpp' ! -name '*_test.cpp' ! -name '*fuzz*' ! -name '*Fuzz*')
for sub in utils host_utils hashing; do
  if [ -d "${WORK}/hidl-tools/${sub}" ]; then
    HIDL_SRCS="${HIDL_SRCS} $(find "${WORK}/hidl-tools/${sub}" -maxdepth 1 -name '*.cpp' ! -name '*_test.cpp' ! -name '*fuzz*')"
  fi
done

HIDL_INCS=""
for d in $(find "${WORK}/hidl-tools" -maxdepth 4 -type d \( -name 'include*' -o -name 'hidl-util' -o -name 'hidl-hash' \)); do
  HIDL_INCS="${HIDL_INCS} -I${d}"
done

g++ -std=c++17 -O2 -w \
  -D_GNU_SOURCE \
  -D'__builtin_available(...)=0' \
  -include "${WORK}/hidl-gen-build/host_compat.h" \
  -I"${WORK}/hidl-gen-build" \
  -I"${WORK}/hidl-tools" \
  ${HIDL_INCS} \
  -I"${WORK}/libbase/include" \
  -I"${WORK}/logging/liblog/include" \
  -I"${WORK}/libhwbinder/include" \
  -I"${WORK}/libhidl/base/include" \
  -I"${WORK}/core/include" \
  -I"${WORK}/core/libutils/include" \
  -I/usr/include/jsoncpp \
  hidl-gen_y.cpp hidl-gen_l.cpp host_log_stub.cpp ${HIDL_SRCS} ${LIBBASE_SRCS} \
  -lcrypto -ljsoncpp -lpthread \
  -o "${WORK}/hidl-gen"

"${WORK}/hidl-gen" --version || true

echo "=== [4/5] Generating AOSP 12 HIDL C++ headers ==="
GEN="${WORK}/hidl-gen-out"
mkdir -p "${GEN}"
HIDL_ROOTS="-r android.hardware:${WORK}/hw-if -r android.system:${WORK}/sys-hw-if -r android.hidl:${WORK}/libhidl/transport"

for pkg in \
  android.hidl.base@1.0 \
  android.hidl.manager@1.0 \
  android.hidl.memory@1.0 \
  android.hardware.graphics.common@1.0 \
  android.hardware.graphics.common@1.1 \
  android.hardware.graphics.common@1.2 \
  android.hardware.graphics.allocator@2.0 \
  android.hardware.graphics.mapper@2.0 \
  android.hardware.graphics.mapper@2.1 \
  android.hardware.graphics.mapper@3.0 \
  android.hardware.graphics.mapper@4.0 \
  android.hardware.graphics.composer@2.1 \
  android.system.suspend@1.0; do
  "${WORK}/hidl-gen" -o "${GEN}" -L c++-headers ${HIDL_ROOTS} "${pkg}"
done

# Create tiny empty stub .so libraries matching GSI /system/lib64/ DT_NEEDED names
STUBS="${WORK}/stubs"
mkdir -p "${STUBS}"
cat > "${STUBS}/stub.c" <<'EOF'
void __vguest_stub(void) {}
EOF

for lib in \
  libbinder.so \
  libhidlbase.so \
  libfmq.so \
  libhardware.so \
  libutils.so \
  libcutils.so \
  liblog.so \
  libbase.so \
  libsync.so \
  libc++.so \
  android.hidl.base@1.0.so \
  android.hidl.manager@1.0.so \
  android.hardware.graphics.common@1.0.so \
  android.hardware.graphics.common@1.1.so \
  android.hardware.graphics.common@1.2.so \
  android.hardware.graphics.allocator@2.0.so \
  android.hardware.graphics.mapper@2.0.so \
  android.hardware.graphics.mapper@2.1.so \
  android.hardware.graphics.mapper@3.0.so \
  android.hardware.graphics.mapper@4.0.so \
  android.hardware.graphics.composer@2.1.so \
  android.system.suspend@1.0.so; do
  "${CC_ARM64}" -shared -fPIC "${STUBS}/stub.c" -Wl,-soname,"${lib}" -o "${STUBS}/${lib}"
done

AOSP_INCS=(
  -I"${GEN}"
  -I"${REPO_ROOT}/include"
  -I"${WORK}/libhardware/include"
  -I"${WORK}/libhwbinder/include"
  -I"${WORK}/libhidl/base/include"
  -I"${WORK}/libhidl/transport/include"
  -I"${WORK}/libhidl/libhidlmemory/include"
  -I"${WORK}/libfmq/include"
  -I"${WORK}/libfmq/base"
  -I"${WORK}/libbase/include"
  -I"${WORK}/logging/liblog/include"
  -I"${WORK}/core/include"
  -I"${WORK}/core/libcutils/include"
  -I"${WORK}/core/libutils/include"
  -I"${WORK}/core/libsystem/include"
  -I"${WORK}/core/libsync/include"
  -I"${WORK}/native/include"
  -I"${WORK}/native/libs/nativewindow/include"
  -I"${WORK}/native/libs/nativebase/include"
  -I"${WORK}/native/libs/arect/include"
  -I"${WORK}/native/libs/ui/include"
  -I"${WORK}/native/libs/binder/include"
  -I"${WORK}/native/libs/gralloc/types/include"
  -I"${WORK}/hw-if/graphics/mapper/2.0/utils/passthrough/include"
  -I"${WORK}/hw-if/graphics/mapper/2.0/utils/hal/include"
  -I"${WORK}/hw-if/graphics/allocator/2.0/utils/passthrough/include"
  -I"${WORK}/hw-if/graphics/allocator/2.0/utils/hal/include"
  -I"${WORK}/hw-if/graphics/composer/2.1/utils/passthrough/include"
  -I"${WORK}/hw-if/graphics/composer/2.1/utils/hal/include"
  -I"${WORK}/hw-if/graphics/composer/2.1/utils/command-buffer/include"
  -I"${WORK}/hw-if/graphics/composer/2.1/utils/hwc2on1adapter/include"
  -I"${WORK}/hw-if/graphics/composer/2.1/utils/hwc2onfbadapter/include"
)

COMMON_CXXFLAGS=(
  -std=c++17 -O2 -fPIC -Wno-everything -D__ANDROID_VNDK__
  "${AOSP_INCS[@]}"
)
LINK_FLAGS=(
  -L"${STUBS}"
  -Wl,--no-as-needed
  -Wl,--allow-shlib-undefined
  -Wl,--unresolved-symbols=ignore-all
  -nostdlib++
)

echo "=== [5/5] Cross-compiling arm64-v8a Graphics HALs ==="

# Force NDK libc++ headers to emit AOSP's std::__1:: ABI namespace (not std::__ndk1::)
cat > "${WORK}/aosp_libcpp_abi.h" <<'EOF'
#pragma once
#include <__config_site>
#undef _LIBCPP_ABI_NAMESPACE
#define _LIBCPP_ABI_NAMESPACE __1
extern "C" void abort(void) __attribute__((noreturn));
#define _LIBCPP_VERBOSE_ABORT(...) ::abort()
EOF
cat > "${WORK}/aosp_libcpp_compat.cpp" <<'EOF'
#include <stddef.h>
#include <stdint.h>
namespace std {
inline namespace __1 {
// Polyfill for LLVM 19+ libc++ __hash_memory (absent in AOSP 12's LLVM 12 libc++.so)
__attribute__((visibility("hidden")))
size_t __hash_memory(const void* ptr, size_t len) noexcept {
    const auto* p = static_cast<const uint8_t*>(ptr);
    size_t h = 14695981039346656037ULL;
    for (size_t i = 0; i < len; ++i) {
        h ^= static_cast<size_t>(p[i]);
        h *= 1099511628211ULL;
    }
    return h;
}
}  // namespace __1
}  // namespace std
EOF
AOSP_STL_FLAGS=(-include "${WORK}/aosp_libcpp_abi.h" -fno-exceptions -fno-rtti)

# 1. VGuest Virtual HWC2 HAL (hwcomposer.virt.so — pure C HMI export, static STL)
"${CXX_ARM64}" "${COMMON_CXXFLAGS[@]}" -shared \
  "${REPO_ROOT}/native/src/vguest_hwcomposer.cpp" \
  -static-libstdc++ -llog \
  -o "${OUT}/libvguest_hwcomposer.so"

# 2. AOSP 12 IMapper@2.0 passthrough SP-HAL (wraps gralloc.virt.so)
MAPPER_SRCS=$(find "${WORK}/hw-if/graphics/mapper/2.0/default" -name '*.cpp')
"${CXX_ARM64}" "${COMMON_CXXFLAGS[@]}" "${AOSP_STL_FLAGS[@]}" -shared \
  ${MAPPER_SRCS} "${WORK}/aosp_libcpp_compat.cpp" \
  "${LINK_FLAGS[@]}" \
  -lhidlbase -lhardware -lutils -lcutils -llog -lsync -lc++ \
  "${STUBS}/android.hardware.graphics.mapper@2.0.so" \
  "${STUBS}/android.hardware.graphics.common@1.0.so" \
  -o "${OUT}/libvguest_mapper20_impl.so"

# 3. Self-contained AOSP 12 IAllocator@2.0 binderized service (calls GrallocLoader::load() directly)
cat > "${WORK}/allocator_service_main.cpp" <<'EOF'
#include <allocator-passthrough/2.0/GrallocLoader.h>
#include <android/hardware/graphics/allocator/2.0/IAllocator.h>
#include <hidl/HidlTransportSupport.h>
#include <log/log.h>

using android::sp;
using android::hardware::configureRpcThreadpool;
using android::hardware::joinRpcThreadpool;
using android::hardware::graphics::allocator::V2_0::IAllocator;
using android::hardware::graphics::allocator::V2_0::passthrough::GrallocLoader;

int main() {
    configureRpcThreadpool(4, true /* callerWillJoin */);
    sp<IAllocator> allocator(GrallocLoader::load());
    if (!allocator) {
        ALOGE("VGuest allocator@2.0: GrallocLoader::load() failed");
        return 1;
    }
    if (allocator->registerAsService() != android::OK) {
        ALOGE("VGuest allocator@2.0: registerAsService() failed");
        return 1;
    }
    ALOGI("VGuest allocator@2.0: registered IAllocator/default");
    joinRpcThreadpool();
    return 0;
}
EOF

"${CXX_ARM64}" "${COMMON_CXXFLAGS[@]}" "${AOSP_STL_FLAGS[@]}" -fPIE -pie \
  "${WORK}/allocator_service_main.cpp" "${WORK}/aosp_libcpp_compat.cpp" \
  "${LINK_FLAGS[@]}" \
  -lhidlbase -lhardware -lutils -lcutils -llog -lbase -lc++ \
  "${STUBS}/android.hardware.graphics.allocator@2.0.so" \
  "${STUBS}/android.hardware.graphics.common@1.0.so" \
  -o "${OUT}/libvguest_allocator20_svc.so"

# 4. Self-contained AOSP 12 IComposer@2.1 binderized service (calls HwcLoader::load() directly, no vndbinder dep)
cat > "${WORK}/composer_service_main.cpp" <<'EOF'
#define LOG_TAG "VGuestComposer"
#include <android/hardware/graphics/composer/2.1/IComposer.h>
#include <composer-passthrough/2.1/HwcLoader.h>
#include <hidl/HidlTransportSupport.h>
#include <log/log.h>

using android::sp;
using android::hardware::configureRpcThreadpool;
using android::hardware::joinRpcThreadpool;
using android::hardware::graphics::composer::V2_1::IComposer;
using android::hardware::graphics::composer::V2_1::passthrough::HwcLoader;

int main() {
    configureRpcThreadpool(4, true /* callerWillJoin */);
    sp<IComposer> composer(HwcLoader::load());
    if (!composer) {
        ALOGE("VGuest composer@2.1: HwcLoader::load() failed");
        return 1;
    }
    if (composer->registerAsService() != android::OK) {
        ALOGE("VGuest composer@2.1: registerAsService() failed");
        return 1;
    }
    ALOGI("VGuest composer@2.1: registered IComposer/default");
    joinRpcThreadpool();
    return 0;
}
EOF

COMP_INCS=""
for d in $(find "${WORK}/hw-if/graphics/composer/2.1/utils" -maxdepth 3 -type d -name 'include*'); do
  COMP_INCS="${COMP_INCS} -I${d}"
done
COMP_SRCS=$(find "${WORK}/hw-if/graphics/composer/2.1/utils"   -name '*.cpp' ! -path '*/vts/*' ! -path '*/test/*' ! -path '*/tests/*' ! -path '*/fuzzer/*' ! -name '*Test.cpp' ! -name '*test*.cpp' ! -name '*fuzz*' ! -name '*Fuzz*')
"${CXX_ARM64}" "${COMMON_CXXFLAGS[@]}" "${AOSP_STL_FLAGS[@]}" ${COMP_INCS} -DLOG_TAG='"VGuestComposer"' -DPAGE_SIZE=4096 -fPIE -pie \
  "${WORK}/composer_service_main.cpp" "${WORK}/aosp_libcpp_compat.cpp" ${COMP_SRCS} \
  "${LINK_FLAGS[@]}" \
  -lhidlbase -lfmq -lhardware -lutils -lcutils -llog -lbase -lsync -lc++ \
  "${STUBS}/android.hardware.graphics.composer@2.1.so" \
  "${STUBS}/android.hardware.graphics.mapper@2.0.so" \
  "${STUBS}/android.hardware.graphics.mapper@3.0.so" \
  "${STUBS}/android.hardware.graphics.mapper@4.0.so" \
  "${STUBS}/android.hardware.graphics.common@1.0.so" \
  "${STUBS}/android.hardware.graphics.common@1.1.so" \
  "${STUBS}/android.hardware.graphics.common@1.2.so" \
  -o "${OUT}/libvguest_composer21_svc.so"

# 5. Virtualized AOSP 12 ISystemSuspend@1.0 service (zero /sys/power/* or /sys/class/wakeup deps)
cat > "${WORK}/suspend_service_main.cpp" <<'CPPEOF'
#define LOG_TAG "VGuestSuspend"
#include <android/system/suspend/1.0/ISystemSuspend.h>
#include <android/system/suspend/1.0/IWakeLock.h>
#include <binder/Binder.h>
#include <binder/IServiceManager.h>
#include <binder/Parcel.h>
#include <binder/ProcessState.h>
#include <hidl/HidlTransportSupport.h>
#include <log/log.h>
#include <utils/String16.h>

using android::BBinder;
using android::Parcel;
using android::ProcessState;
using android::String16;
using android::defaultServiceManager;
using android::sp;
using android::status_t;
using android::hardware::Return;
using android::hardware::Void;
using android::hardware::configureRpcThreadpool;
using android::hardware::joinRpcThreadpool;
using android::hardware::hidl_string;
using android::system::suspend::V1_0::ISystemSuspend;
using android::system::suspend::V1_0::IWakeLock;
using android::system::suspend::V1_0::WakeLockType;

struct VGuestWakeLock : public IWakeLock {
    Return<void> release() override { return Void(); }
};

struct VGuestSystemSuspend : public ISystemSuspend {
    Return<sp<IWakeLock>> acquireWakeLock(WakeLockType, const hidl_string&) override {
        return sp<IWakeLock>(new VGuestWakeLock());
    }
};

class VGuestSuspendControlBinder : public BBinder {
public:
    explicit VGuestSuspendControlBinder(bool is_internal) : is_internal_(is_internal) {}
    status_t onTransact(uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags) override {
        if (code == android::IBinder::INTERFACE_TRANSACTION) {
            reply->writeString16(String16(is_internal_
                ? "android.system.suspend.internal.ISuspendControlServiceInternal"
                : "android.system.suspend.ISuspendControlService"));
            return android::OK;
        }
        if (code >= android::IBinder::FIRST_CALL_TRANSACTION && code <= android::IBinder::LAST_CALL_TRANSACTION) {
            (void)data;
            if (reply) {
                reply->writeInt32(0);  // binder::Status::EX_NONE
                // code 1 is registerCallback / enableAutosuspend -> return true; others -> 0/false/empty vec
                reply->writeInt32(code == 1 ? 1 : 0);
            }
            return android::OK;
        }
        return BBinder::onTransact(code, data, reply, flags);
    }
private:
    bool is_internal_;
};

int main() {
    ProcessState::self()->startThreadPool();
    auto sm = defaultServiceManager();
    if (sm != nullptr) {
        sm->addService(String16("suspend_control"), new VGuestSuspendControlBinder(false));
        sm->addService(String16("suspend_control_internal"), new VGuestSuspendControlBinder(true));
        ALOGI("VGuest suspend@1.0: registered suspend_control + suspend_control_internal");
    }

    configureRpcThreadpool(2, true /* callerWillJoin */);
    sp<ISystemSuspend> svc(new VGuestSystemSuspend());
    if (svc->registerAsService() != android::OK) {
        ALOGE("VGuest suspend@1.0: registerAsService() failed");
        return 1;
    }
    ALOGI("VGuest suspend@1.0: registered ISystemSuspend/default");
    joinRpcThreadpool();
    return 0;
}
CPPEOF

"${CXX_ARM64}" "${COMMON_CXXFLAGS[@]}" "${AOSP_STL_FLAGS[@]}" -fPIE -pie \
  "${WORK}/suspend_service_main.cpp" "${WORK}/aosp_libcpp_compat.cpp" \
  "${LINK_FLAGS[@]}" \
  -lbinder -lhidlbase -lutils -lcutils -llog -lbase -lc++ \
  "${STUBS}/android.system.suspend@1.0.so" \
  -o "${OUT}/libvguest_suspend_svc.so"

"${STRIP}" --strip-unneeded "${OUT}"/*.so
for f in libvguest_mapper20_impl.so libvguest_allocator20_svc.so libvguest_composer21_svc.so libvguest_suspend_svc.so; do
  if "${READELF}" -s "${OUT}/${f}" | grep -qE "UND.*(_ZTI|_ZTS|__ndk1|__libcpp_verbose_abort|__hash_memory)"; then
    echo "ERROR: ${f} still references NDK __ndk1 or RTTI _ZTI symbols!"
    "${READELF}" -s "${OUT}/${f}" | grep -E "UND.*(_ZTI|_ZTS|__ndk1|__libcpp_verbose_abort|__hash_memory)" | head -n 10
    exit 1
  fi
done
echo "Verified: ZERO __ndk1 or RTTI _ZTI undefined symbols in AOSP-linked graphics HALs."
ls -lh "${OUT}"/
for f in "${OUT}"/*.so; do
  echo "--- DT_NEEDED for $(basename "$f") ---"
  "${READELF}" -d "$f" | grep NEEDED || true
done
