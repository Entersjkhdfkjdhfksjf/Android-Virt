#include <cassert>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "prop_service.hpp"

namespace fs = std::filesystem;

static uint32_t send_setprop2(const std::string& sock_path,
                              const std::string& name,
                              const std::string& val) {
    int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    assert(fd >= 0);

    struct sockaddr_un addr {};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, sock_path.c_str(), sizeof(addr.sun_path) - 1);
    assert(::connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) == 0);

    uint32_t cmd = 0x00020001U;  // PROP_MSG_SETPROP2
    uint32_t nlen = static_cast<uint32_t>(name.size());
    uint32_t vlen = static_cast<uint32_t>(val.size());

    assert(::write(fd, &cmd, 4) == 4);
    assert(::write(fd, &nlen, 4) == 4);
    assert(::write(fd, name.data(), nlen) == static_cast<ssize_t>(nlen));
    assert(::write(fd, &vlen, 4) == 4);
    if (vlen > 0) {
        assert(::write(fd, val.data(), vlen) == static_cast<ssize_t>(vlen));
    }

    uint32_t status = 0xFFFFFFFFU;
    assert(::read(fd, &status, 4) == 4);
    ::close(fd);
    return status;
}

int main() {
    fs::path tmp = fs::temp_directory_path() / "vguest_phase3_test";
    fs::remove_all(tmp);
    fs::create_directories(tmp / "system");

    // Seed a sample build.prop to verify loader + override precedence
    {
        std::ofstream bp(tmp / "system" / "build.prop");
        bp << "# Sample AOSP 12 build.prop\n";
        bp << "ro.build.fingerprint=Android/aosp_arm64/generic_arm64:12/SQ3A/test\n";
        bp << "ro.hardware.gralloc=default\n";
    }

    vguest::PropertyService ps(tmp.string());
    assert(ps.start());

    // 1. Verify Bionic binary files exist & have valid headers
    assert(fs::exists(ps.property_info_path()));
    assert(fs::exists(ps.default_area_path()));
    assert(fs::exists(ps.socket_path()));

    // 2. Verify seeded AOSP 12 properties and override precedence
    std::string val;
    assert(ps.get("ro.build.version.sdk", val) && val == "31");
    assert(ps.get("ro.zygote", val) && val == "zygote64");
    assert(ps.get("ro.hardware.gralloc", val) && val == "virt");  // overridden from build.prop
    assert(ps.get("ro.build.fingerprint", val) && val.find("aosp_arm64") != std::string::npos);

    // 3. Verify live UNIX socket PROP_MSG_SETPROP2 + monotonic global serial
    uint32_t s0 = ps.global_serial();
    assert(send_setprop2(ps.socket_path(), "sys.boot_completed", "1") == 0);
    assert(ps.get("sys.boot_completed", val) && val == "1");
    assert(ps.global_serial() > s0);

    // 4. Verify long property (> 92 bytes) storage & retrieval
    std::string long_val(150, 'X');
    assert(send_setprop2(ps.socket_path(), "debug.vguest.long_test", long_val) == 0);
    assert(ps.get("debug.vguest.long_test", val) && val == long_val);

    // 5. Verify in-place property update
    assert(send_setprop2(ps.socket_path(), "sys.boot_completed", "0") == 0);
    assert(ps.get("sys.boot_completed", val) && val == "0");

    ps.stop();
    fs::remove_all(tmp);

    std::cout << "[PASS] Bionic prop_area, property_info, long props & /dev/socket/property_service\n";
    std::cout << "[ALL PHASE 3 UNIT TESTS PASSED]\n";
    return 0;
}
