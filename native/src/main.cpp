#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "supervisor.hpp"

namespace {

void print_usage(const char* argv0) {
    std::fprintf(stderr,
                 "Usage: %s --rootfs <dir> [--meta-db <rootfs_meta.db>] "
                 "[--transport auto|trace|unotify] [--uid <id>] [--gid <id>] "
                 "[--verbose] -- <guest_cmd> [args...]\n",
                 argv0);
}

}  // namespace

int main(int argc, char** argv) {
    vguest::SupervisorConfig cfg;
    std::vector<std::string> guest_argv;
    std::vector<std::string> guest_env = {
        "PATH=/system/bin:/system/xbin:/vendor/bin:/apex/com.android.runtime/bin:/apex/com.android.art/bin",
        "ANDROID_ROOT=/system",
        "ANDROID_DATA=/data",
        "ANDROID_STORAGE=/storage",
        "HOME=/data/local/tmp",
        "TMPDIR=/data/local/tmp",
    };

    int i = 1;
    for (; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--") {
            ++i;
            break;
        } else if (arg == "--rootfs" && i + 1 < argc) {
            cfg.rootfs_root = argv[++i];
        } else if (arg == "--meta-db" && i + 1 < argc) {
            cfg.meta_db_path = argv[++i];
        } else if (arg == "--transport" && i + 1 < argc) {
            std::string t = argv[++i];
            if (t == "trace") cfg.transport = vguest::InterceptionTransport::kPtraceTrace;
            else if (t == "unotify") cfg.transport = vguest::InterceptionTransport::kUserNotif;
            else cfg.transport = vguest::InterceptionTransport::kAuto;
        } else if (arg == "--uid" && i + 1 < argc) {
            uint32_t u = static_cast<uint32_t>(std::strtoul(argv[++i], nullptr, 10));
            cfg.initial_creds.uid = cfg.initial_creds.euid = cfg.initial_creds.suid = u;
        } else if (arg == "--gid" && i + 1 < argc) {
            uint32_t g = static_cast<uint32_t>(std::strtoul(argv[++i], nullptr, 10));
            cfg.initial_creds.gid = cfg.initial_creds.egid = cfg.initial_creds.sgid = g;
        } else if (arg == "--verbose") {
            cfg.verbose = true;
        } else {
            print_usage(argv[0]);
            return 2;
        }
    }

    for (; i < argc; ++i) {
        guest_argv.emplace_back(argv[i]);
    }

    if (cfg.rootfs_root.empty() || guest_argv.empty()) {
        print_usage(argv[0]);
        return 2;
    }

    vguest::Supervisor sup(std::move(cfg));
    return sup.run(guest_argv, guest_env);
}
