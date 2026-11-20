#include "boot_sequencer.hpp"

#include <fstream>
#include <sstream>
#include <sys/stat.h>

namespace vguest {

namespace {

void mkdir_p(const std::string& dir) {
    std::string cur;
    for (size_t i = 0; i < dir.size(); ++i) {
        cur.push_back(dir[i]);
        if (dir[i] == '/' && cur.size() > 1) {
            ::mkdir(cur.c_str(), 0755);
        }
    }
    ::mkdir(cur.c_str(), 0755);
}

std::string trim(const std::string& s) {
    size_t a = 0;
    while (a < s.size() && (s[a] == ' ' || s[a] == '\t' || s[a] == '\r' || s[a] == '\n')) ++a;
    size_t b = s.size();
    while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t' || s[b - 1] == '\r' || s[b - 1] == '\n')) --b;
    return s.substr(a, b - a);
}

}  // namespace

BootSequencer::BootSequencer(std::string rootfs_root)
    : rootfs_root_(std::move(rootfs_root)) {
    if (rootfs_root_.size() > 1 && rootfs_root_.back() == '/') {
        rootfs_root_.pop_back();
    }
}

std::vector<std::string> BootSequencer::load_init_environ() const {
    std::vector<std::string> env = {
        "PATH=/system/bin:/system/xbin:/vendor/bin:/apex/com.android.runtime/bin:/apex/com.android.art/bin",
        "ANDROID_ROOT=/system",
        "ANDROID_DATA=/data",
        "ANDROID_STORAGE=/storage",
        "ANDROID_ART_ROOT=/apex/com.android.art",
        "ANDROID_I18N_ROOT=/apex/com.android.i18n",
        "ANDROID_TZDATA_ROOT=/apex/com.android.tzdata",
        "ANDROID_RUNTIME_ROOT=/apex/com.android.runtime",
        "HOME=/data/local/tmp",
        "TMPDIR=/data/local/tmp",
    };

    // Parse AOSP 12 /init.environ.rc (or /system/etc/init/init.environ.rc) for export KEY VALUE lines
    const std::string candidates[] = {
        rootfs_root_ + "/init.environ.rc",
        rootfs_root_ + "/system/etc/init/init.environ.rc",
    };
    for (const auto& path : candidates) {
        std::ifstream in(path);
        if (!in.is_open()) continue;
        std::string line;
        while (std::getline(in, line)) {
            std::string t = trim(line);
            if (t.rfind("export ", 0) != 0) continue;
            std::istringstream iss(t.substr(7));
            std::string key, val;
            if (!(iss >> key)) continue;
            std::getline(iss, val);
            val = trim(val);
            if (!key.empty() && !val.empty()) {
                env.push_back(key + "=" + val);
            }
        }
        break;
    }
    return env;
}

bool BootSequencer::provision_vintf_manifest() const {
    std::string vintf_dir = rootfs_root_ + "/vendor/etc/vintf";
    mkdir_p(vintf_dir);
    mkdir_p(rootfs_root_ + "/data/dalvik-cache/arm64");
    mkdir_p(rootfs_root_ + "/data/system");
    mkdir_p(rootfs_root_ + "/data/misc/apexdata");
    mkdir_p(rootfs_root_ + "/data/app");
    mkdir_p(rootfs_root_ + "/data/data");

    const char* kManifestXml = R"XML(<manifest version="4.0" type="device" target-level="6">
    <hal format="hidl">
        <name>android.hardware.graphics.allocator</name>
        <transport>hwbinder</transport>
        <version>4.0</version>
        <interface>
            <name>IAllocator</name>
            <instance>default</instance>
        </interface>
    </hal>
    <hal format="hidl">
        <name>android.hardware.graphics.mapper</name>
        <transport arch="64">passthrough</transport>
        <version>4.0</version>
        <interface>
            <name>IMapper</name>
            <instance>default</instance>
        </interface>
    </hal>
    <hal format="hidl">
        <name>android.hardware.graphics.composer</name>
        <transport>hwbinder</transport>
        <version>2.4</version>
        <interface>
            <name>IComposer</name>
            <instance>default</instance>
        </interface>
    </hal>
    <hal format="hidl">
        <name>android.hardware.health</name>
        <transport>hwbinder</transport>
        <version>2.1</version>
        <interface>
            <name>IHealth</name>
            <instance>default</instance>
        </interface>
    </hal>
</manifest>
)XML";

    std::ofstream out(vintf_dir + "/manifest.xml", std::ios::trunc);
    if (!out.is_open()) return false;
    out << kManifestXml;
    return out.good();
}

std::string BootSequencer::build_stage_script(BootStage stage) const {
    if (stage == BootStage::kIpc) {
        return
            "echo '=== [Stage 1] Booting 3 Isolated Binder Managers ==='\n"
            "/system/bin/servicemanager &\n"
            "P_SM=$!\n"
            "/system/bin/hwservicemanager &\n"
            "P_HW=$!\n"
            "if [ -x /system/bin/vndservicemanager ]; then /system/bin/vndservicemanager & P_VND=$!; fi\n"
            "sleep 1\n"
            "echo '--- /dev/binder service list ---'\n"
            "/system/bin/service list\n"
            "echo '--- VINTF manifest check ---'\n"
            "ls -la /vendor/etc/vintf/manifest.xml\n"
            "echo '--- Active IPC daemons ---'\n"
            "kill -0 $P_SM 2>/dev/null && echo 'servicemanager: ALIVE' || echo 'servicemanager: DEAD'\n"
            "kill -0 $P_HW 2>/dev/null && echo 'hwservicemanager: ALIVE' || echo 'hwservicemanager: DEAD'\n"
            "kill $P_SM $P_HW $P_VND 2>/dev/null || true\n";
    }

    if (stage == BootStage::kArt) {
        return
            "echo '=== [Stage 2] AOSP 12 ART VM (dalvikvm64) Smoke Test ==='\n"
            "echo \"BOOTCLASSPATH=$BOOTCLASSPATH\"\n"
            "echo \"ANDROID_ART_ROOT=$ANDROID_ART_ROOT\"\n"
            "if [ -x /apex/com.android.art/bin/dalvikvm64 ]; then\n"
            "  /apex/com.android.art/bin/dalvikvm64 -Xnoimage-dex2oat -version\n"
            "elif [ -x /system/bin/dalvikvm64 ]; then\n"
            "  /system/bin/dalvikvm64 -Xnoimage-dex2oat -version\n"
            "else\n"
            "  echo 'dalvikvm64 not found'\n"
            "fi\n"
            "echo '--- Checking app_process64 binary ---'\n"
            "ls -la /system/bin/app_process64\n";
    }

    // BootStage::kFull — Full deterministic AOSP 12 runtime bring-up
    return
        "echo '=== [Stage 3] Full AOSP 12 Runtime Bring-Up ==='\n"
        "echo '[1/4] Starting servicemanager, hwservicemanager, vndservicemanager...'\n"
        "/system/bin/servicemanager &\n"
        "P_SM=$!\n"
        "/system/bin/hwservicemanager &\n"
        "P_HW=$!\n"
        "if [ -x /system/bin/vndservicemanager ]; then /system/bin/vndservicemanager & P_VND=$!; fi\n"
        "sleep 1\n"
        "echo '[2/4] Starting installd (if present)...'\n"
        "if [ -x /system/bin/installd ]; then /system/bin/installd & P_INST=$!; fi\n"
        "echo '[3/4] Launching app_process64 (--zygote --start-system-server)...'\n"
        "/system/bin/app_process64 -Xzygote /system/bin --zygote --start-system-server --socket-name=zygote &\n"
        "P_ZYG=$!\n"
        "echo '[4/4] Monitoring boot progress (15s diagnostic window)...'\n"
        "i=0\n"
        "while [ $i -lt 15 ]; do\n"
        "  sleep 1\n"
        "  i=$((i + 1))\n"
        "  if ! kill -0 $P_ZYG 2>/dev/null; then\n"
        "    echo \"[!] zygote64 exited at t=${i}s\"\n"
        "    break\n"
        "  fi\n"
        "  if [ $((i % 5)) -eq 0 ]; then\n"
        "    echo \"[t=${i}s] zygote64 ALIVE — querying services:\"\n"
        "    /system/bin/service list | head -n 15\n"
        "  fi\n"
        "done\n"
        "kill $P_ZYG $P_INST $P_SM $P_HW $P_VND 2>/dev/null || true\n";
}

}  // namespace vguest
