#include "path_translator.hpp"

#include <climits>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace vguest {

namespace {

bool starts_with(std::string_view s, std::string_view prefix) {
    return s.size() >= prefix.size() && s.substr(0, prefix.size()) == prefix;
}

bool is_host_passthru_dev(std::string_view p) {
    return p == "/dev/null" || p == "/dev/zero" || p == "/dev/full" ||
           p == "/dev/urandom" || p == "/dev/random" || p == "/dev/ashmem" ||
           p == "/dev/tty" || p == "/dev/ptmx" || starts_with(p, "/dev/pts/");
}

bool ends_with(std::string_view s, std::string_view suf) {
    return s.size() >= suf.size() && s.substr(s.size() - suf.size()) == suf;
}

bool is_virtual_proc_path(std::string_view p) {
    if (p == "/proc/mounts" || p == "/proc/uptime" || p == "/proc/self/mounts" || p == "/proc/self/mountinfo" ||
        p == "/proc/self/status" || p == "/proc/self/maps") {
        return true;
    }
    if (starts_with(p, "/proc/")) {
        if (ends_with(p, "/attr/current") || ends_with(p, "/attr/exec") ||
            ends_with(p, "/attr/prev") || ends_with(p, "/attr/fscreate") ||
            ends_with(p, "/attr/sockcreate") || ends_with(p, "/attr/keycreate")) {
            return true;
        }
        auto rest = p.substr(6);
        auto slash = rest.find('/');
        if (slash != std::string_view::npos && slash > 0) {
            auto tail = rest.substr(slash);
            if (tail == "/status" || tail == "/maps" || tail == "/mountinfo" || tail == "/mounts") {
                return true;
            }
        }
    }
    return false;
}

bool is_virtual_sys_path(std::string_view p) {
    return p == "/sys/fs/selinux/enforce" || p == "/sys/fs/selinux/checkreqprot" ||
           p == "/sys/fs/selinux/status" || p == "/sys/fs/selinux/access" ||
           p == "/sys/fs/selinux/context" ||
           p == "/sys/power/wake_lock" || p == "/sys/power/wake_unlock" ||
           p == "/sys/power/state" || p == "/sys/power/wakeup_count";
}

bool is_virtual_binder_path(std::string_view p) {
    return p == "/dev/binder" || p == "/dev/hwbinder" || p == "/dev/vndbinder";
}

}  // namespace

PathTranslator::PathTranslator(std::string rootfs_root)
    : rootfs_root_(normalize_posix(rootfs_root)) {
    if (rootfs_root_.size() > 1 && rootfs_root_.back() == '/') {
        rootfs_root_.pop_back();
    }
}

std::string PathTranslator::normalize_posix(std::string_view path) {
    if (path.empty()) return "/";
    std::vector<std::string_view> parts;
    size_t i = 0;
    const size_t n = path.size();
    while (i < n) {
        while (i < n && path[i] == '/') ++i;
        size_t start = i;
        while (i < n && path[i] != '/') ++i;
        if (i > start) {
            std::string_view seg = path.substr(start, i - start);
            if (seg == ".") {
                continue;
            } else if (seg == "..") {
                if (!parts.empty()) parts.pop_back();
            } else {
                parts.push_back(seg);
            }
        }
    }
    if (parts.empty()) return "/";
    std::string out;
    out.reserve(path.size() + 1);
    for (auto seg : parts) {
        out.push_back('/');
        out.append(seg);
    }
    return out;
}

std::string PathTranslator::host_to_guest(std::string_view host_path) const {
    std::string norm = normalize_posix(host_path);
    if (norm == rootfs_root_) return "/";
    if (starts_with(norm, rootfs_root_) && norm.size() > rootfs_root_.size() &&
        norm[rootfs_root_.size()] == '/') {
        return norm.substr(rootfs_root_.size());
    }
    return norm;
}

std::string PathTranslator::resolve_dirfd_guest(pid_t pid, int dirfd) const {
    char proc_link[128];
    if (dirfd == AT_FDCWD) {
        std::snprintf(proc_link, sizeof(proc_link), "/proc/%d/cwd", static_cast<int>(pid));
    } else {
        std::snprintf(proc_link, sizeof(proc_link), "/proc/%d/fd/%d", static_cast<int>(pid), dirfd);
    }
    char buf[PATH_MAX];
    ssize_t n = ::readlink(proc_link, buf, sizeof(buf) - 1);
    if (n <= 0) return "/";
    buf[n] = '\0';
    return host_to_guest(std::string_view(buf, static_cast<size_t>(n)));
}

PathKind PathTranslator::classify_guest_path(std::string_view guest_abs) const {
    if (is_virtual_binder_path(guest_abs)) return PathKind::kVirtualBinder;
    if (starts_with(guest_abs, "/dev/input/event")) return PathKind::kVirtualInput;
    if (is_host_passthru_dev(guest_abs)) return PathKind::kHostPassThru;
    if (is_virtual_proc_path(guest_abs)) return PathKind::kVirtualProc;
    if (is_virtual_sys_path(guest_abs)) return PathKind::kVirtualSys;
    if (starts_with(guest_abs, "/sys/fs/selinux/class/") || guest_abs == "/sys/fs/selinux/class") {
        return PathKind::kNormalRootfs;
    }
    // Allow read-only host /proc and /sys fallthrough for unvirtualized nodes (e.g. /sys/devices/system/cpu)
    if (starts_with(guest_abs, "/proc/") || guest_abs == "/proc" ||
        starts_with(guest_abs, "/sys/") || guest_abs == "/sys") {
        return PathKind::kHostPassThru;
    }
    return PathKind::kNormalRootfs;
}

std::string PathTranslator::resolve_symlinks_in_rootfs(std::string_view guest_abs,
                                                       bool follow_final_symlink) const {
    constexpr int kMaxSymloop = 40;
    std::string cur = normalize_posix(guest_abs);

    for (int depth = 0; depth < kMaxSymloop; ++depth) {
        if (cur == "/") return cur;

        // Walk path components from root so intermediate symlinks (e.g. /bin/sh -> /system/bin/sh)
        // are resolved inside rootfs without escaping to host root.
        std::vector<std::string_view> segs;
        size_t pos = 1;
        while (pos < cur.size()) {
            size_t slash = cur.find('/', pos);
            if (slash == std::string::npos) {
                segs.push_back(std::string_view(cur).substr(pos));
                break;
            }
            segs.push_back(std::string_view(cur).substr(pos, slash - pos));
            pos = slash + 1;
        }

        std::string built;
        bool restarted = false;
        for (size_t idx = 0; idx < segs.size(); ++idx) {
            built.push_back('/');
            built.append(segs[idx]);
            const bool is_last = (idx + 1 == segs.size());
            if (is_last && !follow_final_symlink) break;

            // Don't lstat inside host-passthru /proc, /sys, /dev
            if (classify_guest_path(built) != PathKind::kNormalRootfs) continue;

            std::string host_cand = rootfs_root_ + built;
            struct stat st {};
            if (::lstat(host_cand.c_str(), &st) == 0 && S_ISLNK(st.st_mode)) {
                char target[PATH_MAX];
                ssize_t tlen = ::readlink(host_cand.c_str(), target, sizeof(target) - 1);
                if (tlen > 0) {
                    target[tlen] = '\0';
                    std::string next_path;
                    if (target[0] == '/') {
                        next_path = target;
                    } else {
                        auto parent_slash = built.rfind('/');
                        std::string parent =
                            (parent_slash == 0) ? "/" : built.substr(0, parent_slash);
                        next_path = parent + "/" + target;
                    }
                    for (size_t r = idx + 1; r < segs.size(); ++r) {
                        next_path.push_back('/');
                        next_path.append(segs[r]);
                    }
                    cur = normalize_posix(next_path);
                    restarted = true;
                    break;
                }
            }
        }
        if (!restarted) return cur;
    }
    return cur;
}

TranslatedPath PathTranslator::translate_absolute(std::string_view guest_abs,
                                                  bool follow_final_symlink) const {
    std::string norm = normalize_posix(guest_abs);
    if (norm == rootfs_root_ ||
        (starts_with(norm, rootfs_root_) && norm.size() > rootfs_root_.size() &&
         norm[rootfs_root_.size()] == '/')) {
        norm = host_to_guest(norm);
    }
    PathKind initial_kind = classify_guest_path(norm);
    if (initial_kind != PathKind::kNormalRootfs) {
        std::string host = (initial_kind == PathKind::kVirtualInput) ? (rootfs_root_ + norm) : norm;
        return TranslatedPath{initial_kind, norm, std::move(host)};
    }

    std::string resolved = resolve_symlinks_in_rootfs(norm, follow_final_symlink);
    PathKind final_kind = classify_guest_path(resolved);
    if (final_kind != PathKind::kNormalRootfs) {
        return TranslatedPath{final_kind, resolved, resolved};
    }

    std::string host = (resolved == "/") ? rootfs_root_ : (rootfs_root_ + resolved);
    return TranslatedPath{PathKind::kNormalRootfs, std::move(resolved), std::move(host)};
}

TranslatedPath PathTranslator::translate(pid_t pid, int dirfd, std::string_view raw_path,
                                         bool follow_final_symlink) const {
    if (raw_path.empty()) {
        std::string base = resolve_dirfd_guest(pid, dirfd);
        return translate_absolute(base, follow_final_symlink);
    }
    if (raw_path.front() == '/') {
        return translate_absolute(raw_path, follow_final_symlink);
    }
    std::string base = resolve_dirfd_guest(pid, dirfd);
    std::string combined = (base == "/") ? ("/" + std::string(raw_path))
                                         : (base + "/" + std::string(raw_path));
    return translate_absolute(combined, follow_final_symlink);
}

std::string PathTranslator::translate_unix_socket(std::string_view raw_sun_path,
                                                  bool is_abstract) const {
    if (is_abstract) {
        return "vguest_" + std::string(raw_sun_path);
    }
    return translate_absolute(raw_sun_path, true).host_path;
}

}  // namespace vguest
