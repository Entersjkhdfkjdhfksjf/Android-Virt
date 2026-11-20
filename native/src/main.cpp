#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "boot_sequencer.hpp"
#include "supervisor.hpp"

namespace {

void print_usage(const char* argv0) {
    std::fprintf(stderr,
                 "Usage: %s --rootfs <dir> [--meta-db <rootfs_meta.db>] "
                 "[--transport auto|trace|unotify] [--uid <id>] [--gid <id>] "
                 "[--boot ipc|art|full] [--verbose] [-- <guest_cmd> [args...]]\n",
                 argv0);
}

}  // namespace

int main(int argc, char** argv) {
    vguest::SupervisorConfig cfg;
    vguest::BootStage boot_stage = vguest::BootStage::kNone;
    std::vector<std::string> guest_argv;

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
        } else if (arg == "--boot" && i + 1 < argc) {
            std::string stage = argv[++i];
            if (stage == "ipc") boot_stage = vguest::BootStage::kIpc;
            else if (stage == "art") boot_stage = vguest::BootStage::kArt;
            else if (stage == "full") boot_stage = vguest::BootStage::kFull;
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

    if (cfg.rootfs_root.empty() || (boot_stage == vguest::BootStage::kNone && guest_argv.empty())) {
        print_usage(argv[0]);
        return 2;
    }

    vguest::BootSequencer boot(cfg.rootfs_root);
    std::vector<std::string> guest_env = boot.load_init_environ();

    if (boot_stage != vguest::BootStage::kNone) {
        (void)boot.provision_vintf_manifest();
        guest_argv = {"/system/bin/sh", "-c", boot.build_stage_script(boot_stage)};
    }

    vguest::Supervisor sup(std::move(cfg));
    return sup.run(guest_argv, guest_env);
}
