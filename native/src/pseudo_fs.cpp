#include "pseudo_fs.hpp"

#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef __NR_memfd_create
#if defined(__aarch64__)
#define __NR_memfd_create 279
#elif defined(__x86_64__)
#define __NR_memfd_create 319
#endif
#endif

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

namespace vguest {

namespace {

bool starts_with(std::string_view s, std::string_view p) {
    return s.size() >= p.size() && s.substr(0, p.size()) == p;
}

bool ends_with(std::string_view s, std::string_view suf) {
    return s.size() >= suf.size() && s.substr(s.size() - suf.size()) == suf;
}

}  // namespace

PseudoFs::PseudoFs(std::string rootfs_root) : rootfs_root_(std::move(rootfs_root)) {
    if (rootfs_root_.size() > 1 && rootfs_root_.back() == '/') {
        rootfs_root_.pop_back();
    }
}

std::string PseudoFs::build_proc_mounts() const {
    return "rootfs / rootfs ro,seclabel 0 0\n"
           "/dev/block/dm-0 /system ext4 ro,seclabel,relatime 0 0\n"
           "tmpfs /apex tmpfs rw,seclabel,nosuid,nodev,noexec,relatime,mode=755 0 0\n"
           "/dev/block/dm-1 /data ext4 rw,seclabel,nosuid,nodev,noatime 0 0\n"
           "tmpfs /dev tmpfs rw,seclabel,nosuid,relatime,mode=755 0 0\n"
           "proc /proc proc rw,relatime,gid=3009,hidepid=2 0 0\n"
           "sysfs /sys sysfs rw,seclabel,relatime 0 0\n"
           "selinuxfs /sys/fs/selinux selinuxfs rw,relatime 0 0\n";
}

std::string PseudoFs::build_proc_mountinfo() const {
    return "1 1 0:1 / / ro - rootfs rootfs ro,seclabel\n"
           "2 1 253:0 / /system ro,relatime - ext4 /dev/block/dm-0 ro,seclabel\n"
           "3 1 0:2 / /apex rw,nosuid,nodev,noexec - tmpfs tmpfs rw,seclabel\n"
           "4 1 253:1 / /data rw,nosuid,nodev,noatime - ext4 /dev/block/dm-1 rw,seclabel\n"
           "5 1 0:3 / /dev rw,nosuid - tmpfs tmpfs rw,seclabel\n"
           "6 1 0:4 / /proc rw - proc proc rw\n"
           "7 1 0:5 / /sys rw - sysfs sysfs rw,seclabel\n";
}

std::string PseudoFs::build_proc_status(pid_t pid, const VirtualCreds& creds) const {
    char path[64];
    std::snprintf(path, sizeof(path), "/proc/%d/status", static_cast<int>(pid));
    std::ifstream in(path);
    if (!in.is_open()) return "";

    std::ostringstream out;
    std::string line;
    char fmt_buf[128];
    while (std::getline(in, line)) {
        if (starts_with(line, "Uid:")) {
            std::snprintf(fmt_buf, sizeof(fmt_buf), "Uid:\t%u\t%u\t%u\t%u",
                          creds.uid, creds.euid, creds.suid, creds.euid);
            out << fmt_buf << "\n";
        } else if (starts_with(line, "Gid:")) {
            std::snprintf(fmt_buf, sizeof(fmt_buf), "Gid:\t%u\t%u\t%u\t%u",
                          creds.gid, creds.egid, creds.sgid, creds.egid);
            out << fmt_buf << "\n";
        } else if (starts_with(line, "CapInh:")) {
            std::snprintf(fmt_buf, sizeof(fmt_buf), "CapInh:\t%016llx",
                          static_cast<unsigned long long>(creds.cap_inheritable));
            out << fmt_buf << "\n";
        } else if (starts_with(line, "CapPrm:")) {
            std::snprintf(fmt_buf, sizeof(fmt_buf), "CapPrm:\t%016llx",
                          static_cast<unsigned long long>(creds.cap_permitted));
            out << fmt_buf << "\n";
        } else if (starts_with(line, "CapEff:")) {
            std::snprintf(fmt_buf, sizeof(fmt_buf), "CapEff:\t%016llx",
                          static_cast<unsigned long long>(creds.cap_effective));
            out << fmt_buf << "\n";
        } else {
            out << line << "\n";
        }
    }
    return out.str();
}

std::string PseudoFs::build_proc_maps(pid_t pid) const {
    char path[64];
    std::snprintf(path, sizeof(path), "/proc/%d/maps", static_cast<int>(pid));
    std::ifstream in(path);
    if (!in.is_open()) return "";

    std::ostringstream out;
    std::string line;
    while (std::getline(in, line)) {
        size_t pos = line.find(rootfs_root_);
        if (pos != std::string::npos) {
            line.erase(pos, rootfs_root_.size());
        }
        out << line << "\n";
    }
    return out.str();
}

std::string PseudoFs::generate_content(pid_t pid, std::string_view guest_path,
                                       const VirtualCreds& creds) const {
    if (guest_path == "/sys/fs/selinux/enforce" || guest_path == "/sys/fs/selinux/checkreqprot") {
        return "0\n";
    }
    if (guest_path == "/sys/fs/selinux/status") {
        // 4096-byte mmap-able Linux selinux_status_t: version=1, sequence=0, enforcing=0, policyload=1, deny_unknown=0
        std::string page(4096, '\0');
        uint32_t hdr[5] = {1u, 0u, 0u, 1u, 0u};
        std::memcpy(page.data(), hdr, sizeof(hdr));
        return page;
    }
    if (guest_path == "/proc/uptime") {
        return "1000.00 2000.00\n";
    }
    if (ends_with(guest_path, "/attr/current")) {
        std::string ctx = creds.selinux_ctx;
        ctx.push_back('\0');
        return ctx;
    }
    if (guest_path == "/proc/mounts" || ends_with(guest_path, "/mounts")) {
        return build_proc_mounts();
    }
    if (ends_with(guest_path, "/mountinfo")) {
        return build_proc_mountinfo();
    }
    if (ends_with(guest_path, "/status")) {
        return build_proc_status(pid, creds);
    }
    if (ends_with(guest_path, "/maps")) {
        return build_proc_maps(pid);
    }
    return "";
}

int PseudoFs::open_virtual_memfd(pid_t pid, std::string_view guest_path,
                                 const VirtualCreds& creds) const {
    std::string content = generate_content(pid, guest_path, creds);
    int fd = static_cast<int>(::syscall(__NR_memfd_create, "vguest_pseudofs", MFD_CLOEXEC));
    if (fd < 0) return -1;

    size_t written = 0;
    while (written < content.size()) {
        ssize_t n = ::write(fd, content.data() + written, content.size() - written);
        if (n <= 0) {
            ::close(fd);
            return -1;
        }
        written += static_cast<size_t>(n);
    }
    ::lseek(fd, 0, SEEK_SET);
    return fd;
}

}  // namespace vguest
