#include "boot_sequencer.hpp"

#include <algorithm>
#include <dirent.h>
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

bool file_exists(const std::string& path) {
    struct stat st {};
    return ::stat(path.c_str(), &st) == 0 && S_ISREG(st.st_mode);
}

std::string trim(const std::string& s) {
    size_t a = 0;
    while (a < s.size() && (s[a] == ' ' || s[a] == '\t' || s[a] == '\r' || s[a] == '\n')) ++a;
    size_t b = s.size();
    while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t' || s[b - 1] == '\r' || s[b - 1] == '\n')) --b;
    return s.substr(a, b - a);
}

std::string build_fallback_bootclasspath(const std::string& rootfs) {
    // Canonical AOSP 12 bootclasspath order: ART core -> i18n -> conscrypt -> framework -> apex javalib
    const char* ordered[] = {
        "/apex/com.android.art/javalib/core-oj.jar",
        "/apex/com.android.art/javalib/core-libart.jar",
        "/apex/com.android.art/javalib/okhttp.jar",
        "/apex/com.android.art/javalib/bouncycastle.jar",
        "/apex/com.android.art/javalib/apache-xml.jar",
        "/apex/com.android.i18n/javalib/core-icu4j.jar",
        "/apex/com.android.conscrypt/javalib/conscrypt.jar",
        "/system/framework/framework.jar",
        "/system/framework/framework-graphics.jar",
        "/system/framework/ext.jar",
        "/system/framework/telephony-common.jar",
        "/system/framework/voip-common.jar",
        "/system/framework/ims-common.jar",
        "/system/framework/framework-atb-backward-compatibility.jar",
    };

    std::vector<std::string> jars;
    for (const char* g : ordered) {
        if (file_exists(rootfs + g)) jars.emplace_back(g);
    }

    // Append any additional flattened /apex/*/javalib/framework-*.jar
    std::string apex_dir = rootfs + "/apex";
    DIR* ad = ::opendir(apex_dir.c_str());
    if (ad) {
        std::vector<std::string> extra;
        while (struct dirent* ent = ::readdir(ad)) {
            std::string mod = ent->d_name;
            if (mod == "." || mod == ".." || mod.find('@') != std::string::npos) continue;
            std::string jdir = apex_dir + "/" + mod + "/javalib";
            DIR* jd = ::opendir(jdir.c_str());
            if (!jd) continue;
            while (struct dirent* jent = ::readdir(jd)) {
                std::string jf = jent->d_name;
                if (jf.size() > 4 && jf.substr(jf.size() - 4) == ".jar") {
                    std::string gpath = "/apex/" + mod + "/javalib/" + jf;
                    if (std::find(jars.begin(), jars.end(), gpath) == jars.end()) {
                        extra.push_back(gpath);
                    }
                }
            }
            ::closedir(jd);
        }
        ::closedir(ad);
        std::sort(extra.begin(), extra.end());
        for (auto& e : extra) jars.push_back(std::move(e));
    }

    std::string joined;
    for (size_t i = 0; i < jars.size(); ++i) {
        if (i > 0) joined.push_back(':');
        joined.append(jars[i]);
    }
    return joined;
}

std::string build_fallback_systemserverclasspath(const std::string& rootfs) {
    const char* ordered[] = {
        "/system/framework/com.android.location.provider.jar",
        "/system/framework/services.jar",
        "/system/framework/ethernet-service.jar",
    };
    std::string joined;
    for (const char* g : ordered) {
        if (file_exists(rootfs + g)) {
            if (!joined.empty()) joined.push_back(':');
            joined.append(g);
        }
    }
    return joined;
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

    bool has_bcp = false;
    bool has_sscp = false;

    const std::string candidates[] = {
        rootfs_root_ + "/init.environ.rc",
        rootfs_root_ + "/system/etc/init/init.environ.rc",
        rootfs_root_ + "/system/etc/init/hw/init.environ.rc",
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
                if (key == "BOOTCLASSPATH") has_bcp = true;
                if (key == "SYSTEMSERVERCLASSPATH") has_sscp = true;
                env.push_back(key + "=" + val);
            }
        }
        if (has_bcp) break;
    }

    if (!has_bcp) {
        std::string bcp = build_fallback_bootclasspath(rootfs_root_);
        if (!bcp.empty()) {
            env.push_back("BOOTCLASSPATH=" + bcp);
            env.push_back("DEX2OATBOOTCLASSPATH=" + bcp);
        }
    }
    if (!has_sscp) {
        std::string sscp = build_fallback_systemserverclasspath(rootfs_root_);
        if (!sscp.empty()) {
            env.push_back("SYSTEMSERVERCLASSPATH=" + sscp);
        }
    }
    return env;
}

bool BootSequencer::provision_vintf_manifest() const {
    const char* dirs[] = {
        "/vendor/etc/vintf",
        "/data/dalvik-cache/arm64",
        "/data/system",
        "/data/system_ce/0",
        "/data/system_de/0",
        "/data/misc/apexdata/com.android.art/dalvik-cache",
        "/data/misc/installd",
        "/data/misc/user/0",
        "/data/misc_ce/0",
        "/data/misc_de/0",
        "/data/user/0",
        "/data/user_de/0",
        "/data/media/0",
        "/data/vendor",
        "/data/vendor_ce/0",
        "/data/vendor_de/0",
        "/data/app",
        "/data/data",
        "/data/anr",
        "/data/tombstones",
        "/data/local/tmp",
        "/data/system/users/0",
        "/data/system/sync",
        "/data/system/dropbox",
        "/data/system/usagestats",
        "/data/system/job",
        "/data/system/netstats",
        "/data/system/procstats",
        "/data/system/shared_prefs",
        "/data/system/graphicsstats",
        "/data/misc/keystore",
        "/data/misc/gatekeeper",
        "/data/misc/profiles/cur/0",
        "/data/misc/profiles/ref",
        "/data/misc/wifi",
        "/data/misc/bluedroid",
        "/data/misc/adb",
        "/cache/recovery",
        "/mnt/user/0/self",
        "/mnt/user/0/emulated/0",
        "/mnt/user/0/package",
        "/mnt/pass_through/0/emulated/0",
        "/mnt/androidwritable/0/emulated/0",
        "/mnt/installer/0/emulated/0",
        "/mnt/runtime/default",
        "/mnt/runtime/read",
        "/mnt/runtime/write",
        "/mnt/runtime/full",
        "/storage/self",
        "/storage/emulated/0/Android/data",
        "/storage/emulated/0/Android/obb",
        "/sys/fs/selinux/class/service_manager/perms",
        "/sys/fs/selinux/class/hwservice_manager/perms",
        "/sys/fs/selinux/class/property_service/perms",
        "/sys/fs/selinux/class/binder/perms",
        "/sys/fs/selinux/class/keystore_key/perms",
    };
    for (const char* d : dirs) {
        mkdir_p(rootfs_root_ + d);
    }

    // Populate real /sys/fs/selinux/class/* directories so libselinux discover_class()
    // can opendir(.../perms) and read index/perm files natively.
    auto write_text_file = [&](const std::string& rel, const char* txt) {
        std::ofstream f(rootfs_root_ + rel, std::ios::trunc);
        if (f.is_open()) f << txt;
    };
    write_text_file("/sys/fs/selinux/class/service_manager/index", "1\n");
    write_text_file("/sys/fs/selinux/class/service_manager/perms/add", "1\n");
    write_text_file("/sys/fs/selinux/class/service_manager/perms/find", "2\n");
    write_text_file("/sys/fs/selinux/class/service_manager/perms/list", "3\n");
    write_text_file("/sys/fs/selinux/class/hwservice_manager/index", "2\n");
    write_text_file("/sys/fs/selinux/class/hwservice_manager/perms/add", "1\n");
    write_text_file("/sys/fs/selinux/class/hwservice_manager/perms/find", "2\n");
    write_text_file("/sys/fs/selinux/class/hwservice_manager/perms/list", "3\n");
    write_text_file("/sys/fs/selinux/class/property_service/index", "3\n");
    write_text_file("/sys/fs/selinux/class/property_service/perms/set", "1\n");
    write_text_file("/sys/fs/selinux/class/binder/index", "4\n");
    write_text_file("/sys/fs/selinux/class/binder/perms/impersonate", "1\n");
    write_text_file("/sys/fs/selinux/class/binder/perms/call", "2\n");
    write_text_file("/sys/fs/selinux/class/binder/perms/set_context_mgr", "3\n");
    write_text_file("/sys/fs/selinux/class/binder/perms/transfer", "4\n");
    write_text_file("/sys/fs/selinux/class/keystore_key/index", "5\n");
    write_text_file("/sys/fs/selinux/class/keystore_key/perms/use", "1\n");
    write_text_file("/sys/fs/selinux/class/keystore_key/perms/insert", "2\n");
    write_text_file("/sys/fs/selinux/class/keystore_key/perms/delete", "3\n");
    write_text_file("/sys/fs/selinux/class/keystore_key/perms/get_info", "4\n");

    const char* kManifestXml = R"XML(<manifest version="4.0" type="device" target-level="6">
    <hal format="hidl">
        <name>android.hardware.graphics.allocator</name>
        <transport>hwbinder</transport>
        <version>2.0</version>
        <interface>
            <name>IAllocator</name>
            <instance>default</instance>
        </interface>
    </hal>
    <hal format="hidl">
        <name>android.hardware.graphics.mapper</name>
        <transport arch="64">passthrough</transport>
        <version>2.0</version>
        <interface>
            <name>IMapper</name>
            <instance>default</instance>
        </interface>
    </hal>
    <hal format="hidl">
        <name>android.hardware.graphics.composer</name>
        <transport>hwbinder</transport>
        <version>2.1</version>
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

    // If /linkerconfig/ld.config.txt is missing or empty (e.g., Docker-exported Redroid rootfs),
    // synthesize a complete AOSP 12 linkerconfig with all APEX + system + sphal namespaces.
    {
        std::string ld_dir = rootfs_root_ + "/linkerconfig";
        ::mkdir(ld_dir.c_str(), 0755);
        std::string ld_path = ld_dir + "/ld.config.txt";
        struct stat ld_st {};
        if (::stat(ld_path.c_str(), &ld_st) != 0 || ld_st.st_size < 64) {
            std::vector<std::pair<std::string, std::string>> apex_ns; // (ns_name, dir_name)
            std::string common_paths =
                "/system/lib64:/system_ext/lib64:/product/lib64:/vendor/lib64:/vendor/lib64/hw:/vendor/lib64/egl";
            if (DIR* ad = ::opendir((rootfs_root_ + "/apex").c_str())) {
                while (struct dirent* ent = ::readdir(ad)) {
                    std::string name = ent->d_name;
                    if (name == "." || name == ".." || name.find('@') != std::string::npos) continue;
                    std::string ns = name;
                    for (char& ch : ns) {
                        if (ch == '.' || ch == '-') ch = '_';
                    }
                    apex_ns.emplace_back(ns, name);
                    common_paths += ":/apex/" + name + "/lib64";
                    if (name == "com.android.runtime") {
                        common_paths += ":/apex/com.android.runtime/lib64/bionic";
                    }
                }
                ::closedir(ad);
            }
            std::string add_ns = "system,sphal,vndk";
            for (const auto& [ns, _] : apex_ns) {
                add_ns += "," + ns;
            }
            std::ostringstream cfg;
            cfg << "dir.system = /system/bin\n"
                << "dir.system = /system_ext/bin\n"
                << "dir.system = /product/bin\n"
                << "dir.system = /apex/com.android.art/bin\n"
                << "dir.system = /apex/com.android.runtime/bin\n"
                << "dir.vendor = /vendor/bin\n"
                << "dir.vendor = /vendor/bin/hw\n\n"
                << "[system]\n"
                << "additional.namespaces = " << add_ns << "\n"
                << "namespace.default.isolated = false\n"
                << "namespace.default.search.paths = " << common_paths << "\n"
                << "namespace.default.permitted.paths = /system:/system_ext:/product:/vendor:/apex:/data\n"
                << "namespace.default.links = " << add_ns << "\n"
                << "namespace.default.link.system.allow_all_shared_libs = true\n"
                << "namespace.default.link.sphal.allow_all_shared_libs = true\n"
                << "namespace.default.link.vndk.allow_all_shared_libs = true\n";
            for (const auto& [ns, _] : apex_ns) {
                cfg << "namespace.default.link." << ns << ".allow_all_shared_libs = true\n";
            }
            auto emit_ns = [&](const std::string& ns, const std::string& extra_path) {
                cfg << "\nnamespace." << ns << ".isolated = false\n"
                    << "namespace." << ns << ".visible = true\n"
                    << "namespace." << ns << ".search.paths = "
                    << (extra_path.empty() ? common_paths : (extra_path + ":" + common_paths)) << "\n"
                    << "namespace." << ns << ".permitted.paths = /system:/system_ext:/product:/vendor:/apex:/data\n"
                    << "namespace." << ns << ".links = default\n"
                    << "namespace." << ns << ".link.default.allow_all_shared_libs = true\n";
            };
            emit_ns("system", "");
            emit_ns("sphal", "/vendor/lib64/egl:/vendor/lib64/hw:/vendor/lib64");
            emit_ns("vndk", "/system/lib64/vndk-31:/system/lib64/vndk-sp-31");
            for (const auto& [ns, dir_name] : apex_ns) {
                emit_ns(ns, "/apex/" + dir_name + "/lib64");
            }
            cfg << "\n[vendor]\n"
                << "additional.namespaces = system,sphal\n"
                << "namespace.default.isolated = false\n"
                << "namespace.default.search.paths = /vendor/lib64:/vendor/lib64/hw:/vendor/lib64/egl:" << common_paths << "\n"
                << "namespace.default.permitted.paths = /vendor:/system:/system_ext:/product:/apex:/data\n"
                << "namespace.default.links = system,sphal\n"
                << "namespace.default.link.system.allow_all_shared_libs = true\n"
                << "namespace.default.link.sphal.allow_all_shared_libs = true\n";
            emit_ns("system", "");
            emit_ns("sphal", "/vendor/lib64/egl:/vendor/lib64/hw:/vendor/lib64");

            std::ofstream lout(ld_path, std::ios::trunc);
            lout << cfg.str();
        }
    }

    // Ensure /linkerconfig/ld.config.txt exports a visible `system` namespace for libart OAT loading
    {
        std::string ld_path = rootfs_root_ + "/linkerconfig/ld.config.txt";
        std::ifstream lin(ld_path);
        if (lin.is_open()) {
            std::ostringstream ss;
            ss << lin.rdbuf();
            std::string content = ss.str();
            lin.close();
            if (content.find("namespace.system.visible = true") == std::string::npos) {
                // Inject `system` into additional.namespaces and append namespace.system block under [system]
                size_t pos = content.find("additional.namespaces = ");
                if (pos != std::string::npos) {
                    size_t val_pos = pos + 24;
                    if (content.compare(val_pos, 7, "system,") != 0) {
                        content.insert(val_pos, "system,");
                    }
                }
                size_t links_pos = content.find("namespace.default.links = ");
                if (links_pos != std::string::npos) {
                    size_t val_pos = links_pos + 26;
                    if (content.compare(val_pos, 7, "system,") != 0) {
                        content.insert(val_pos, "system,");
                    }
                }
                size_t vend_pos = content.find("\n[vendor]");
                std::string sys_ns =
                    "\nnamespace.default.link.system.allow_all_shared_libs = true\n"
                    "\nnamespace.system.isolated = false\n"
                    "namespace.system.visible = true\n"
                    "namespace.system.search.paths = /system/lib64:/system_ext/lib64:/product/lib64:/vendor/lib64:/apex/com.android.art/lib64:/apex/com.android.runtime/lib64:/apex/com.android.runtime/lib64/bionic:/apex/com.android.i18n/lib64:/apex/com.android.conscrypt/lib64\n"
                    "namespace.system.permitted.paths = /system:/system_ext:/product:/vendor:/apex:/data\n"
                    "namespace.system.links = default\n"
                    "namespace.system.link.default.allow_all_shared_libs = true\n";
                if (vend_pos != std::string::npos) {
                    content.insert(vend_pos, sys_ns);
                } else {
                    content.append(sys_ns);
                }
                std::ofstream lout(ld_path, std::ios::trunc);
                lout << content;
            }
        }
    }

    // Ensure EVERY non-default namespace (com_android_art, com_android_i18n, com_android_conscrypt, etc.)
    // has `visible = true` so libnativeloader's android_get_exported_namespace() finds them all!
    {
        std::string ld_path = rootfs_root_ + "/linkerconfig/ld.config.txt";
        std::ifstream lin(ld_path);
        if (lin.is_open()) {
            std::vector<std::string> lines;
            std::string line;
            while (std::getline(lin, line)) lines.push_back(line);
            lin.close();

            std::vector<std::string> out_lines;
            bool changed = false;
            for (size_t i = 0; i < lines.size(); ++i) {
                out_lines.push_back(lines[i]);
                const std::string& l = lines[i];
                const std::string suf = ".isolated = false";
                if (l.rfind("namespace.", 0) == 0 && l.size() > suf.size() &&
                    l.compare(l.size() - suf.size(), suf.size(), suf) == 0 &&
                    l.rfind("namespace.default.", 0) != 0) {
                    std::string ns_prefix = l.substr(0, l.size() - suf.size());
                    std::string vis_line = ns_prefix + ".visible = true";
                    bool has_vis = (i + 1 < lines.size() && lines[i + 1] == vis_line);
                    if (!has_vis) {
                        out_lines.push_back(vis_line);
                        changed = true;
                    }
                }
            }
            if (changed) {
                std::ofstream lout(ld_path, std::ios::trunc);
                for (const auto& ol : out_lines) lout << ol << "\n";
            }
        }
    }

    // Remove unstarted VINTF manifest fragments (e.g., Redroid's power/lights/sensors lazy AIDL XMLs)
    // so servicemanager doesn't block forever trying to lazy-start HALs we haven't launched.
    {
        std::string frag_dir = rootfs_root_ + "/vendor/etc/vintf/manifest";
        if (DIR* fd = ::opendir(frag_dir.c_str())) {
            while (struct dirent* ent = ::readdir(fd)) {
                std::string name = ent->d_name;
                if (name == "." || name == "..") continue;
                std::remove((frag_dir + "/" + name).c_str());
            }
            ::closedir(fd);
        }
    }

    std::ofstream out(rootfs_root_ + "/vendor/etc/vintf/manifest.xml", std::ios::trunc);
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
            "echo '--- Active IPC daemons ---'\n"
            "kill -0 $P_SM 2>/dev/null && echo 'servicemanager: ALIVE' || echo 'servicemanager: DEAD'\n"
            "kill -0 $P_HW 2>/dev/null && echo 'hwservicemanager: ALIVE' || echo 'hwservicemanager: DEAD'\n"
            "kill $P_SM $P_HW $P_VND 2>/dev/null || true\n";
    }

    if (stage == BootStage::kArt) {
        return
            "echo '=== [Stage 2] AOSP 12 ART VM (dalvikvm64) Smoke Test ==='\n"
            "echo \"BOOTCLASSPATH length: ${#BOOTCLASSPATH}\"\n"
            "if [ -x /apex/com.android.art/bin/dalvikvm64 ]; then\n"
            "  /apex/com.android.art/bin/dalvikvm64 -Xnoimage-dex2oat -version\n"
            "fi\n";
    }

    return
        "echo '=== [Stage 3] Full AOSP 12 Runtime Bring-Up ==='\n"
        "echo \"BOOTCLASSPATH length: ${#BOOTCLASSPATH} | SYSTEMSERVERCLASSPATH length: ${#SYSTEMSERVERCLASSPATH}\"\n"
        "echo '[1/4] Starting servicemanager, hwservicemanager, vndservicemanager...'\n"
        "/system/bin/servicemanager &\n"
        "P_SM=$!\n"
        "/system/bin/hwservicemanager &\n"
        "P_HW=$!\n"
        "if [ -x /system/bin/vndservicemanager ]; then /system/bin/vndservicemanager & P_VND=$!; fi\n"
        "sleep 1\n"
        "echo '[2/4] Starting graphics HALs (allocator@2.0, composer@2.1), installd, system_suspend & surfaceflinger...'\n"
        "if [ -x /vendor/bin/hw/android.system.suspend@1.0-service ]; then /vendor/bin/hw/android.system.suspend@1.0-service & P_SUSP=$!; elif [ -x /system/bin/hw/android.system.suspend@1.0-service ]; then /system/bin/hw/android.system.suspend@1.0-service & P_SUSP=$!; fi\n"
        "if [ -x /vendor/bin/hw/android.hardware.graphics.allocator@2.0-service ]; then /vendor/bin/hw/android.hardware.graphics.allocator@2.0-service & P_ALLOC=$!; fi\n"
        "if [ -x /vendor/bin/hw/android.hardware.graphics.composer@2.1-service ]; then /vendor/bin/hw/android.hardware.graphics.composer@2.1-service & P_COMP=$!; fi\n"
        "if [ -x /system/bin/installd ]; then /system/bin/installd & P_INST=$!; fi\n"
        "sleep 1\n"
        "if [ -x /system/bin/surfaceflinger ]; then /system/bin/surfaceflinger & P_SF=$!; fi\n"
        "sleep 1\n"
        "echo '[3/4] Launching app_process64 (--zygote --start-system-server)...'\n"
        "/system/bin/app_process64 -Xzygote /system/bin --zygote --start-system-server --socket-name=zygote </dev/null >/dev/null 2>&1 &\n"
        "P_ZYG=$!\n"
        "echo '[4/4] Monitoring boot progress (60s boot window)...'\n"
        "i=0\n"
        "while [ $i -lt 60 ]; do\n"
        "  sleep 1\n"
        "  i=$((i + 1))\n"
        "  if ! kill -0 $P_ZYG 2>/dev/null; then\n"
        "    echo \"[!] zygote64 exited at t=${i}s\"\n"
        "    break\n"
        "  fi\n"
        "  if [ $((i % 10)) -eq 0 ]; then\n"
        "    echo \"[t=${i}s] zygote64 ALIVE — querying services:\"\n"
        "    (/system/bin/service list | head -n 25) & P_SL=$!\n"
        "    (sleep 3; kill $P_SL 2>/dev/null || true) & P_TK=$!\n"
        "    wait $P_SL 2>/dev/null || true\n"
        "    kill $P_TK 2>/dev/null || true\n"
        "  fi\n"
        "done\n"
        "kill $P_ZYG $P_SF $P_COMP $P_ALLOC $P_INST $P_SUSP $P_SM $P_HW $P_VND 2>/dev/null || true\n";
}

}  // namespace vguest
