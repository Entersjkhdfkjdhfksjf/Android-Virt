#pragma once

#include <string>
#include <utility>
#include <vector>

namespace vguest {

enum class BootStage {
    kNone,
    kIpc,   // Stage 1: servicemanager + hwservicemanager + vndservicemanager (3 Binder domains)
    kArt,   // Stage 2: AOSP 12 ART VM (dalvikvm64 / app_process64) with GSI BOOTCLASSPATH
    kFull,  // Stage 3: Full Android 12 bring-up (IPC + installd + surfaceflinger + zygote64/system_server)
};

class BootSequencer {
public:
    explicit BootSequencer(std::string rootfs_root);

    // Parses <rootfs>/init.environ.rc and returns KEY=VALUE environment entries
    // (BOOTCLASSPATH, DEX2OATBOOTCLASSPATH, SYSTEMSERVERCLASSPATH, ANDROID_ART_ROOT, etc.).
    std::vector<std::string> load_init_environ() const;

    // Writes minimal Treble VINTF /vendor/etc/vintf/manifest.xml so hwservicemanager &
    // SurfaceFlinger recognize our virtual graphics/power/health HAL declarations.
    bool provision_vintf_manifest() const;

    // Generates the deterministic shell bootstrap script for the requested BootStage.
    std::string build_stage_script(BootStage stage) const;

private:
    std::string rootfs_root_;
};

}  // namespace vguest
