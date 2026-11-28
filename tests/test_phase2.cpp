#include <cassert>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <linux/seccomp.h>
#include <sys/stat.h>
#include <unistd.h>

#include "cred_table.hpp"
#include "path_translator.hpp"
#include "pseudo_fs.hpp"
#include "runtime_meta.hpp"
#include "seccomp_bpf.hpp"

namespace fs = std::filesystem;

static void test_path_translator() {
    fs::path tmp = fs::temp_directory_path() / "vguest_test_rootfs";
    fs::remove_all(tmp);
    fs::create_directories(tmp / "system" / "bin");
    fs::create_directories(tmp / "apex" / "com.android.runtime" / "bin");
    std::ofstream(tmp / "apex" / "com.android.runtime" / "bin" / "linker64") << "ELF";
    fs::create_symlink("/system/bin", tmp / "bin");
    fs::create_symlink("/apex/com.android.runtime/bin/linker64",
                       tmp / "system" / "bin" / "linker64");

    vguest::PathTranslator tr(tmp.string());

    // 1. Traversal escape prevention
    auto esc = tr.translate_absolute("/../../../../etc/passwd");
    assert(esc.kind == vguest::PathKind::kNormalRootfs);
    assert(esc.guest_path == "/etc/passwd");
    assert(esc.host_path == (tmp / "etc" / "passwd").string());

    // 2. Guest-rooted symlink resolution confined inside rootfs
    auto lnk = tr.translate_absolute("/bin/linker64", true);
    assert(lnk.guest_path == "/apex/com.android.runtime/bin/linker64");
    assert(lnk.host_path == (tmp / "apex" / "com.android.runtime" / "bin" / "linker64").string());

    // 3. Reverse host -> guest stripping (including symlinked rootfs_root)
    assert(tr.host_to_guest(lnk.host_path) == "/apex/com.android.runtime/bin/linker64");
    assert(tr.host_to_guest(tmp.string()) == "/");

    fs::path link_root = fs::temp_directory_path() / "vguest_test_rootfs_link";
    fs::remove_all(link_root);
    fs::create_symlink(tmp, link_root);
    vguest::PathTranslator tr_link(link_root.string());
    assert(tr_link.host_to_guest((fs::canonical(tmp) / "system" / "bin").string()) == "/system/bin");
    fs::remove_all(link_root);

    // 4. Special path classifications
    assert(tr.translate_absolute("/dev/null").kind == vguest::PathKind::kHostPassThru);
    assert(tr.translate_absolute("/dev/binder").kind == vguest::PathKind::kVirtualBinder);
    assert(tr.translate_absolute("/dev/hwbinder").kind == vguest::PathKind::kVirtualBinder);
    assert(tr.translate_absolute("/dev/input/event0").kind == vguest::PathKind::kVirtualInput);
    assert(tr.translate_absolute("/proc/mounts").kind == vguest::PathKind::kVirtualProc);
    assert(tr.translate_absolute("/proc/self/attr/current").kind == vguest::PathKind::kVirtualProc);
    assert(tr.translate_absolute("/sys/fs/selinux/enforce").kind == vguest::PathKind::kVirtualSys);

    // 5. Abstract UNIX socket namespacing
    assert(tr.translate_unix_socket("zygote", true) == "vguest_zygote");

    fs::remove_all(tmp);
    std::cout << "[PASS] PathTranslator confinement, symlinks & classifications\n";
}

static void test_pseudo_fs() {
    vguest::PseudoFs pfs("/data/user/0/com.example/files/rootfs");
    vguest::VirtualCreds creds;
    creds.uid = creds.euid = creds.suid = 1000;
    creds.gid = creds.egid = creds.sgid = 1000;
    creds.selinux_ctx = "u:r:system_server:s0";

    assert(pfs.generate_content(::getpid(), "/sys/fs/selinux/enforce", creds) == "0\n");

    std::string ctx = pfs.generate_content(::getpid(), "/proc/self/attr/current", creds);
    assert(ctx.find("u:r:system_server:s0") == 0);

    std::string mounts = pfs.generate_content(::getpid(), "/proc/mounts", creds);
    assert(mounts.find("/system") != std::string::npos);
    assert(mounts.find("/apex") != std::string::npos);

    std::string status = pfs.generate_content(::getpid(), "/proc/self/status", creds);
    assert(status.find("Uid:\t1000\t1000\t1000\t1000") != std::string::npos);

    int mfd = pfs.open_virtual_memfd(::getpid(), "/sys/fs/selinux/enforce", creds);
    assert(mfd >= 0);
    char buf[8] = {};
    ssize_t n = ::read(mfd, buf, sizeof(buf));
    ::close(mfd);
    assert(n == 2 && buf[0] == '0' && buf[1] == '\n');

    std::cout << "[PASS] PseudoFs synthetic /proc & /sys memfd generation\n";
}

static void test_runtime_meta_store() {
    fs::path tmp = fs::temp_directory_path() / "vguest_test_runtime_meta";
    fs::remove_all(tmp);
    fs::create_directories(tmp / "data" / "system");
    fs::create_directories(tmp / "data" / "data" / "com.android.providers.telephony");
    fs::create_directories(tmp / "data" / "data" / "com.android.systemui" / "cache" / "shaders");
    fs::create_directories(tmp / "data" / "data" / "com.android.systemui" / "code_cache");
    fs::create_directories(tmp / "data" / "user_de" / "0" / "com.android.systemui" / "cache");
    fs::create_directories(tmp / "data" / "user");
    fs::create_symlink("/data/data", tmp / "data" / "user" / "0");

    // Seed /data/system/packages.list as AOSP PackageManagerService writes it
    {
        std::ofstream pl(tmp / "data" / "system" / "packages.list");
        pl << "com.android.providers.telephony 1001 0 /data/user_de/0/com.android.providers.telephony platform:privapp\n";
        pl << "com.android.systemui 10062 0 /data/user_de/0/com.android.systemui platform:privapp\n";
    }

    {
        vguest::RuntimeMetaStore store;
        assert(store.open_and_seed(tmp.string()));

        const auto* tel = store.find("/data/data/com.android.providers.telephony");
        assert(tel && tel->has_uid && tel->uid == 1001 && tel->has_gid && tel->gid == 1001);

        const auto* sui = store.find("/data/data/com.android.systemui");
        assert(sui && sui->uid == 10062 && sui->gid == 10062);

        const auto* sui_cache = store.find("/data/data/com.android.systemui/cache");
        assert(sui_cache && sui_cache->uid == 10062 && sui_cache->gid == 20062);

        const auto* sui_shaders = store.find("/data/data/com.android.systemui/cache/shaders");
        assert(sui_shaders && sui_shaders->uid == 10062 && sui_shaders->gid == 20062);

        const auto* sui_de_cache = store.find("/data/user_de/0/com.android.systemui/cache");
        assert(sui_de_cache && sui_de_cache->uid == 10062 && sui_de_cache->gid == 20062);

        // Verify S_ISGID GID inheritance for new file under cache
        store.set_mode("/data/data/com.android.systemui/cache", 02771);
        assert(store.effective_created_gid("/data/data/com.android.systemui/cache/new.bin", 10062) == 20062);

        // Create file with space & special char, rename subtree, and delete
        fs::create_directories(tmp / "data" / "media" / "0" / "My Dir");
        std::ofstream(tmp / "data" / "media" / "0" / "My Dir" / "file\t1.txt") << "hi";
        store.record_created("/data/media/0/My Dir/file\t1.txt", 1023, 1023);
        fs::rename(tmp / "data" / "media" / "0" / "My Dir",
                   tmp / "data" / "media" / "0" / "Moved Dir");
        store.rename_meta("/data/media/0/My Dir", "/data/media/0/Moved Dir");
        store.set_owner("/data/data/com.android.systemui", 10062, true, 10999, true);

        // Create a transient file that will be removed before reopen -> should be pruned
        std::ofstream(tmp / "data" / "local_gone") << "x";
        store.record_created("/data/local_gone", 2000, 2000);
        fs::remove(tmp / "data" / "local_gone");
        // Intentionally don't call store.close() or flush explicitly — journal is already written!
    }

    // Reopen in a fresh RuntimeMetaStore instance to verify persistence + pruning
    {
        vguest::RuntimeMetaStore reopened;
        assert(reopened.open_and_seed(tmp.string()));
        const auto* sui = reopened.find("/data/data/com.android.systemui");
        assert(sui && sui->uid == 10062 && sui->gid == 10999);
        const auto* sui_cache = reopened.find("/data/data/com.android.systemui/cache");
        assert(sui_cache && sui_cache->has_mode && sui_cache->mode == 02771);
        const auto* moved = reopened.find("/data/media/0/Moved Dir/file\t1.txt");
        assert(moved && moved->uid == 1023 && moved->gid == 1023);
        assert(reopened.find("/data/media/0/My Dir/file\t1.txt") == nullptr);
        assert(reopened.find("/data/local_gone") == nullptr);
    }

    fs::remove_all(tmp);
    std::cout << "[PASS] RuntimeMetaStore persistence, recovery & subtree tracking\n";
}

static void test_cred_registry_and_bpf() {
    vguest::ProcessRegistry reg;
    vguest::VirtualCreds root_creds;
    root_creds.uid = 0;
    root_creds.selinux_ctx = "u:r:init:s0";

    auto& p1 = reg.get_or_create(100, root_creds);
    p1.creds.uid = 1000;
    reg.inherit_from_parent(100, 101);
    auto& p2 = reg.get_or_create(101, root_creds);
    assert(p2.creds.uid == 1000);
    assert(p2.creds.selinux_ctx == "u:r:init:s0");
    reg.erase(100);
    assert(reg.size() == 1);

    auto prog = vguest::build_seccomp_filter(SECCOMP_RET_TRACE);
    assert(prog.size() > 30);
    assert(prog.back().k == SECCOMP_RET_TRACE);
    assert(prog[prog.size() - 2].k == SECCOMP_RET_ALLOW);

    bool unotify = vguest::probe_seccomp_user_notif();
    std::cout << "[PASS] ProcessRegistry & cBPF filter (" << prog.size()
              << " insns, kernel user_notif=" << (unotify ? "yes" : "no") << ")\n";
}

int main() {
    test_path_translator();
    test_pseudo_fs();
    test_runtime_meta_store();
    test_cred_registry_and_bpf();
    std::cout << "[ALL PHASE 2 UNIT TESTS PASSED]\n";
    return 0;
}
