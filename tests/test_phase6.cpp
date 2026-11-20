#include <cassert>
#include <filesystem>
#include <fstream>
#include <iostream>

#include "boot_sequencer.hpp"

namespace fs = std::filesystem;

int main() {
    fs::path tmp = fs::temp_directory_path() / "vguest_phase6_test";
    fs::remove_all(tmp);
    fs::create_directories(tmp);

    // Seed a sample AOSP 12 init.environ.rc
    {
        std::ofstream rc(tmp / "init.environ.rc");
        rc << "# AOSP 12 init.environ.rc\n";
        rc << "on early-init\n";
        rc << "    export BOOTCLASSPATH /apex/com.android.art/javalib/core-oj.jar:/system/framework/framework.jar\n";
        rc << "    export SYSTEMSERVERCLASSPATH /system/framework/services.jar\n";
    }

    vguest::BootSequencer seq(tmp.string());
    auto env = seq.load_init_environ();
    bool has_bcp = false, has_sscp = false;
    for (const auto& e : env) {
        if (e.rfind("BOOTCLASSPATH=/apex/com.android.art/javalib/core-oj.jar", 0) == 0) has_bcp = true;
        if (e == "SYSTEMSERVERCLASSPATH=/system/framework/services.jar") has_sscp = true;
    }
    assert(has_bcp && has_sscp);

    assert(seq.provision_vintf_manifest());
    assert(fs::exists(tmp / "vendor" / "etc" / "vintf" / "manifest.xml"));

    std::string ipc_s = seq.build_stage_script(vguest::BootStage::kIpc);
    std::string art_s = seq.build_stage_script(vguest::BootStage::kArt);
    std::string full_s = seq.build_stage_script(vguest::BootStage::kFull);
    assert(ipc_s.find("hwservicemanager") != std::string::npos);
    assert(art_s.find("dalvikvm64") != std::string::npos);
    assert(full_s.find("--zygote --start-system-server") != std::string::npos);

    fs::remove_all(tmp);
    std::cout << "[PASS] BootSequencer init.environ.rc parser, VINTF manifest & staged boot scripts\n";
    std::cout << "[ALL PHASE 6 UNIT TESTS PASSED]\n";
    return 0;
}
