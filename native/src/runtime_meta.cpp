#include "runtime_meta.hpp"

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace vguest {

namespace {

constexpr size_t kMaxJournalOpsBeforeCompact = 8192;
constexpr int kMaxSeedDepth = 64;

bool write_all(int fd, const char* data, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = ::write(fd, data + off, len - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        off += static_cast<size_t>(n);
    }
    return true;
}

std::vector<std::string> split_tabs(const std::string& line) {
    std::vector<std::string> parts;
    size_t start = 0;
    while (true) {
        size_t pos = line.find('\t', start);
        if (pos == std::string::npos) {
            parts.push_back(line.substr(start));
            break;
        }
        parts.push_back(line.substr(start, pos - start));
        start = pos + 1;
    }
    return parts;
}

bool parse_u32(const std::string& s, uint32_t& out) {
    if (s.empty()) return false;
    char* end = nullptr;
    errno = 0;
    unsigned long v = std::strtoul(s.c_str(), &end, 10);
    if (errno != 0 || end == s.c_str() || *end != '\0' || v > 0xFFFFFFFFUL) {
        return false;
    }
    out = static_cast<uint32_t>(v);
    return true;
}

bool extract_xml_attr(const std::string& tag, const char* attr_name, std::string& out) {
    std::string needle = std::string(" ") + attr_name + "=\"";
    size_t pos = tag.find(needle);
    if (pos == std::string::npos) return false;
    size_t val_start = pos + needle.size();
    size_t val_end = tag.find('"', val_start);
    if (val_end == std::string::npos) return false;
    out = tag.substr(val_start, val_end - val_start);
    return true;
}

uint32_t compute_cache_gid(uint32_t user_id, uint32_t base_uid) {
    uint32_t app_id = base_uid % 100000U;
    if (app_id >= 10000U && app_id <= 19999U) {
        return user_id * 100000U + 20000U + (app_id - 10000U);
    }
    return user_id * 100000U + app_id;
}

bool is_all_digits(const std::string& s) {
    if (s.empty()) return false;
    for (char c : s) {
        if (c < '0' || c > '9') return false;
    }
    return true;
}

bool has_path_prefix(const std::string& path, const std::string& prefix) {
    return path == prefix ||
           (path.size() > prefix.size() && path.compare(0, prefix.size(), prefix) == 0 &&
            path[prefix.size()] == '/');
}

std::string escape_path(const std::string& path) {
    std::string out;
    out.reserve(path.size());
    for (unsigned char c : path) {
        if (c == '%') {
            out.append("%25");
        } else if (c == '\t') {
            out.append("%09");
        } else if (c == '\n') {
            out.append("%0A");
        } else if (c == '\r') {
            out.append("%0D");
        } else {
            out.push_back(static_cast<char>(c));
        }
    }
    return out;
}

bool unescape_path(const std::string& in, std::string& out) {
    out.clear();
    out.reserve(in.size());
    for (size_t i = 0; i < in.size(); ++i) {
        if (in[i] == '%') {
            if (i + 2 >= in.size()) return false;
            char buf[3] = {in[i + 1], in[i + 2], '\0'};
            char* end = nullptr;
            unsigned long v = std::strtoul(buf, &end, 16);
            if (end != buf + 2) return false;
            out.push_back(static_cast<char>(v));
            i += 2;
        } else {
            out.push_back(in[i]);
        }
    }
    return !out.empty();
}

void append_formatted_set_line(std::string& out, const std::string& guest_path,
                               const RuntimeStatMeta& meta) {
    out += "U\t";
    out += (meta.has_uid ? '1' : '0');
    out += '\t';
    out += std::to_string(meta.uid);
    out += '\t';
    out += (meta.has_gid ? '1' : '0');
    out += '\t';
    out += std::to_string(meta.gid);
    out += '\t';
    out += (meta.has_mode ? '1' : '0');
    out += '\t';
    out += std::to_string(meta.mode);
    out += '\t';
    out += escape_path(guest_path);
    out += '\n';
}

}  // namespace

RuntimeMetaStore::~RuntimeMetaStore() {
    close();
}

void RuntimeMetaStore::close() {
    if (journal_fd_ >= 0) {
        ::close(journal_fd_);
        journal_fd_ = -1;
    }
}

void RuntimeMetaStore::parse_packages_list(const std::string& path,
                                           std::unordered_map<std::string, uint32_t>& out) {
    std::ifstream in(path);
    if (!in.is_open()) return;
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty() || line[0] == '#') continue;
        std::istringstream iss(line);
        std::string pkg;
        uint32_t uid = 0;
        if (iss >> pkg >> uid) {
            if (!pkg.empty() && uid < 100000000U) {
                out[pkg] = uid;
            }
        }
    }
}

void RuntimeMetaStore::parse_packages_xml(const std::string& path,
                                          std::unordered_map<std::string, uint32_t>& out) {
    std::ifstream in(path, std::ios::binary);
    if (!in.is_open()) return;
    char hdr[4] = {};
    in.read(hdr, 3);
    if (!in || std::memcmp(hdr, "ABX", 3) == 0) {
        return;  // Binary ABX XML; packages.list provides plain-text UIDs on AOSP 12+
    }
    in.seekg(0, std::ios::beg);
    std::string line;
    while (std::getline(in, line)) {
        if (line.find("<package ") == std::string::npos &&
            line.find("<shared-user ") == std::string::npos) {
            continue;
        }
        std::string name;
        std::string uid_str;
        if (!extract_xml_attr(line, "name", name)) continue;
        if (!extract_xml_attr(line, "userId", uid_str) &&
            !extract_xml_attr(line, "sharedUserId", uid_str)) {
            continue;
        }
        uint32_t uid = 0;
        if (parse_u32(uid_str, uid)) {
            out.emplace(name, uid);
        }
    }
}

std::unordered_map<std::string, uint32_t> RuntimeMetaStore::load_package_uids(
    const std::string& rootfs_root) {
    std::unordered_map<std::string, uint32_t> pkg_uids;
    parse_packages_list(rootfs_root + "/data/system/packages.list", pkg_uids);
    parse_packages_xml(rootfs_root + "/data/system/packages.xml", pkg_uids);
    return pkg_uids;
}

bool RuntimeMetaStore::replay_journal(const std::string& journal_path) {
    std::ifstream in(journal_path);
    if (!in.is_open()) return false;

    std::string line;
    while (std::getline(in, line)) {
        if (line.empty() || line[0] == '#') continue;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        auto fields = split_tabs(line);
        if (fields.empty()) continue;

        const std::string& op = fields[0];
        if (op == "U" && fields.size() == 8) {
            uint32_t has_uid = 0, uid = 0, has_gid = 0, gid = 0, has_mode = 0, mode = 0;
            std::string gpath;
            if (!parse_u32(fields[1], has_uid) || !parse_u32(fields[2], uid) ||
                !parse_u32(fields[3], has_gid) || !parse_u32(fields[4], gid) ||
                !parse_u32(fields[5], has_mode) || !parse_u32(fields[6], mode) ||
                !unescape_path(fields[7], gpath)) {
                continue;
            }
            auto& rm = entries_[gpath];
            if (has_uid != 0) {
                rm.uid = uid;
                rm.has_uid = true;
            }
            if (has_gid != 0) {
                rm.gid = gid;
                rm.has_gid = true;
            }
            if (has_mode != 0) {
                rm.mode = mode;
                rm.has_mode = true;
            }
        } else if (op == "R" && fields.size() >= 3) {
            std::string old_p, new_p;
            if (!unescape_path(fields[1], old_p) || !unescape_path(fields[2], new_p)) {
                continue;
            }
            bool is_exchange = (fields.size() >= 4 && fields[3] == "1");
            apply_rename_map(entries_, old_p, new_p, is_exchange);
        } else if (op == "C" && fields.size() >= 5) {
            std::string src_p, dst_p;
            uint32_t fb_uid = 0, fb_gid = 0;
            if (!unescape_path(fields[1], src_p) || !unescape_path(fields[2], dst_p) ||
                !parse_u32(fields[3], fb_uid) || !parse_u32(fields[4], fb_gid)) {
                continue;
            }
            auto sit = entries_.find(src_p);
            if (sit != entries_.end()) {
                entries_[dst_p] = sit->second;
            } else {
                RuntimeStatMeta rm;
                rm.uid = fb_uid;
                rm.gid = fb_gid;
                rm.has_uid = true;
                rm.has_gid = true;
                entries_[dst_p] = rm;
            }
        } else if (op == "D" && fields.size() == 2) {
            std::string gpath;
            if (unescape_path(fields[1], gpath)) {
                apply_erase_map(entries_, gpath);
            }
        }
    }
    return true;
}

void RuntimeMetaStore::prune_missing() {
    for (auto it = entries_.begin(); it != entries_.end();) {
        struct stat st {};
        std::string host = rootfs_root_ + it->first;
        if (::lstat(host.c_str(), &st) != 0 && (errno == ENOENT || errno == ENOTDIR)) {
            it = entries_.erase(it);
        } else {
            ++it;
        }
    }
}

void RuntimeMetaStore::seed_if_absent(const std::string& guest_path, uid_t uid, gid_t gid) {
    if (entries_.find(guest_path) != entries_.end()) return;
    struct stat st {};
    std::string host = rootfs_root_ + guest_path;
    if (::lstat(host.c_str(), &st) != 0) return;

    RuntimeStatMeta rm;
    rm.uid = uid;
    rm.gid = gid;
    rm.has_uid = true;
    rm.has_gid = true;
    entries_.emplace(guest_path, rm);
}

void RuntimeMetaStore::seed_system_dir_recursive(const std::string& guest_dir,
                                                 const std::string& host_dir,
                                                 int depth) {
    if (depth > 8) return;
    seed_if_absent(guest_dir, 1000, 1000);
    DIR* d = ::opendir(host_dir.c_str());
    if (!d) return;
    while (struct dirent* ent = ::readdir(d)) {
        if (std::strcmp(ent->d_name, ".") == 0 || std::strcmp(ent->d_name, "..") == 0) continue;
        std::string cg = guest_dir + "/" + ent->d_name;
        std::string ch = host_dir + "/" + ent->d_name;
        struct stat st {};
        if (::lstat(ch.c_str(), &st) != 0) continue;
        if (S_ISDIR(st.st_mode)) {
            seed_system_dir_recursive(cg, ch, depth + 1);
        } else {
            seed_if_absent(cg, 1000, 1000);
        }
    }
    ::closedir(d);
}

void RuntimeMetaStore::seed_aosp_data_defaults() {
    struct SeedPair {
        const char* path;
        uid_t uid;
        gid_t gid;
    };
    const SeedPair kDefaults[] = {
        {"/data", 1000, 1000},
        {"/data/data", 1000, 1000},
        {"/data/user", 1000, 1000},
        {"/data/user/0", 0, 0},
        {"/data/user_de", 1000, 1000},
        {"/data/user_de/0", 1000, 1000},
        {"/data/system_ce", 1000, 1000},
        {"/data/system_ce/0", 1000, 1000},
        {"/data/system_de", 1000, 1000},
        {"/data/system_de/0", 1000, 1000},
        {"/data/misc", 1000, 9998},
        {"/data/misc/installd", 0, 0},
        {"/data/misc/keystore", 1017, 1017},
        {"/data/misc/user", 1000, 1000},
        {"/data/misc/user/0", 1000, 1000},
        {"/data/misc/profiles", 1000, 1000},
        {"/data/misc/profiles/cur", 1000, 1000},
        {"/data/misc/profiles/cur/0", 1000, 1000},
        {"/data/misc/profiles/ref", 1000, 1000},
        {"/data/misc_ce", 1000, 1000},
        {"/data/misc_ce/0", 1000, 1000},
        {"/data/misc_de", 1000, 1000},
        {"/data/misc_de/0", 1000, 1000},
        {"/data/app", 1000, 1000},
        {"/data/anr", 1000, 1000},
        {"/data/tombstones", 1000, 1000},
        {"/data/local", 2000, 2000},
        {"/data/local/tmp", 2000, 2000},
        {"/data/media", 1023, 1023},
        {"/data/media/0", 1023, 1023},
        {"/data/dalvik-cache", 0, 0},
        {"/data/dalvik-cache/arm64", 0, 0},
        {"/data/vendor", 0, 0},
        {"/data/vendor_ce", 0, 0},
        {"/data/vendor_ce/0", 0, 0},
        {"/data/vendor_de", 0, 0},
        {"/data/vendor_de/0", 0, 0},
        {"/data/fonts", 1000, 1000},
        {"/data/fonts/files", 1000, 1000},
        {"/data/resource-cache", 1000, 1000},
        {"/data_mirror", 0, 0},
        {"/data_mirror/data_ce", 0, 0},
        {"/data_mirror/data_ce/null", 0, 0},
        {"/data_mirror/data_ce/null/0", 0, 0},
        {"/data_mirror/data_de", 0, 0},
        {"/data_mirror/data_de/null", 0, 0},
        {"/data_mirror/data_de/null/0", 0, 0},
        {"/data_mirror/misc_ce", 0, 0},
        {"/data_mirror/misc_ce/null", 0, 0},
        {"/data_mirror/misc_ce/null/0", 0, 0},
        {"/data_mirror/misc_de", 0, 0},
        {"/data_mirror/misc_de/null", 0, 0},
        {"/data_mirror/misc_de/null/0", 0, 0},
        {"/data_mirror/cur_profiles", 0, 0},
        {"/data_mirror/ref_profiles", 0, 0},
    };
    for (const auto& sp : kDefaults) {
        seed_if_absent(sp.path, sp.uid, sp.gid);
    }

    struct stat sys_st {};
    std::string host_sys = rootfs_root_ + "/data/system";
    if (::lstat(host_sys.c_str(), &sys_st) == 0 && S_ISDIR(sys_st.st_mode)) {
        seed_system_dir_recursive("/data/system", host_sys, 0);
    }
}

void RuntimeMetaStore::seed_pkg_subtree_recursive(const std::string& guest_base,
                                                  const std::string& host_base,
                                                  uint32_t uid, uint32_t normal_gid,
                                                  uint32_t cache_gid,
                                                  bool inside_cache,
                                                  bool is_pkg_root,
                                                  int depth) {
    if (depth > kMaxSeedDepth) return;
    struct stat st {};
    if (::lstat(host_base.c_str(), &st) != 0) return;

    uint32_t node_uid = uid;
    uint32_t node_gid = inside_cache ? cache_gid : normal_gid;
    if (!is_pkg_root && S_ISLNK(st.st_mode)) {
        size_t slash = guest_base.rfind('/');
        if (slash != std::string::npos && guest_base.substr(slash + 1) == "lib") {
            node_uid = 1000;
            node_gid = 1000;
        }
    }
    seed_if_absent(guest_base, node_uid, node_gid);

    if (!S_ISDIR(st.st_mode)) return;
    DIR* d = ::opendir(host_base.c_str());
    if (!d) return;
    while (struct dirent* ent = ::readdir(d)) {
        std::string name = ent->d_name;
        if (name == "." || name == "..") continue;
        bool child_cache = inside_cache ||
                           (is_pkg_root && (name == "cache" || name == "code_cache"));
        seed_pkg_subtree_recursive(guest_base + "/" + name, host_base + "/" + name,
                                   uid, normal_gid, cache_gid, child_cache, false, depth + 1);
    }
    ::closedir(d);
}

void RuntimeMetaStore::seed_package_data_trees(
    const std::unordered_map<std::string, uint32_t>& pkg_uids) {
    if (pkg_uids.empty()) return;

    auto seed_user_dir = [&](const std::string& guest_parent, uint32_t user_id) {
        std::string host_parent = rootfs_root_ + guest_parent;
        struct stat st {};
        if (::lstat(host_parent.c_str(), &st) != 0 || !S_ISDIR(st.st_mode)) return;

        DIR* d = ::opendir(host_parent.c_str());
        if (!d) return;
        while (struct dirent* ent = ::readdir(d)) {
            std::string pkg = ent->d_name;
            if (pkg == "." || pkg == "..") continue;
            auto it = pkg_uids.find(pkg);
            if (it == pkg_uids.end()) continue;
            uint32_t base_uid = it->second;
            uint32_t eff_uid = user_id * 100000U + (base_uid % 100000U);
            uint32_t cgid = compute_cache_gid(user_id, base_uid);
            seed_pkg_subtree_recursive(guest_parent + "/" + pkg, host_parent + "/" + pkg,
                                       eff_uid, eff_uid, cgid, false, true, 0);
        }
        ::closedir(d);
    };

    seed_user_dir("/data/data", 0);

    auto scan_multiuser_root = [&](const std::string& guest_root) {
        std::string host_root = rootfs_root_ + guest_root;
        struct stat rst {};
        if (::lstat(host_root.c_str(), &rst) != 0 || !S_ISDIR(rst.st_mode)) return;
        DIR* ud = ::opendir(host_root.c_str());
        if (!ud) return;
        while (struct dirent* ent = ::readdir(ud)) {
            std::string uname = ent->d_name;
            if (!is_all_digits(uname)) continue;
            uint32_t user_id = 0;
            if (!parse_u32(uname, user_id)) continue;
            seed_user_dir(guest_root + "/" + uname, user_id);
        }
        ::closedir(ud);
    };

    scan_multiuser_root("/data/user");
    scan_multiuser_root("/data/user_de");
}

bool RuntimeMetaStore::compact_locked() {
    if (journal_path_.empty()) return false;
    std::string tmp_path = journal_path_ + ".tmp";
    int fd = ::open(tmp_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0) return false;

    std::string buf = "# vguest_runtime_meta v1\n";
    buf.reserve(buf.size() + entries_.size() * 64);
    for (const auto& [path, rm] : entries_) {
        append_formatted_set_line(buf, path, rm);
    }

    bool ok = write_all(fd, buf.data(), buf.size());
    ::close(fd);
    if (!ok || ::rename(tmp_path.c_str(), journal_path_.c_str()) != 0) {
        ::unlink(tmp_path.c_str());
        return false;
    }

    close();
    journal_fd_ = ::open(journal_path_.c_str(), O_WRONLY | O_APPEND | O_CLOEXEC, 0644);
    journal_ops_ = 0;
    return journal_fd_ >= 0;
}

void RuntimeMetaStore::append_journal_line(const std::string& line) {
    if (journal_fd_ < 0) return;
    (void)write_all(journal_fd_, line.data(), line.size());
    ++journal_ops_;
    if (journal_ops_ >= kMaxJournalOpsBeforeCompact) {
        (void)compact_locked();
    }
}

void RuntimeMetaStore::append_set_line(const std::string& guest_path, const RuntimeStatMeta& meta) {
    std::string line;
    append_formatted_set_line(line, guest_path, meta);
    append_journal_line(line);
}

bool RuntimeMetaStore::open_and_seed(const std::string& rootfs_root, const VfsMetaDb* meta_db) {
    (void)meta_db;
    close();
    entries_.clear();
    journal_ops_ = 0;

    rootfs_root_ = rootfs_root;
    while (rootfs_root_.size() > 1 && rootfs_root_.back() == '/') {
        rootfs_root_.pop_back();
    }
    journal_path_ = rootfs_root_ + "/.vguest_runtime_meta";

    (void)replay_journal(journal_path_);
    prune_missing();
    seed_aosp_data_defaults();
    auto pkg_uids = load_package_uids(rootfs_root_);
    seed_package_data_trees(pkg_uids);

    return compact_locked();
}

const RuntimeStatMeta* RuntimeMetaStore::find(const std::string& guest_path) const {
    auto it = entries_.find(guest_path);
    return (it != entries_.end()) ? &it->second : nullptr;
}

void RuntimeMetaStore::set_owner(const std::string& guest_path, uid_t uid, bool set_uid,
                                 gid_t gid, bool set_gid) {
    if (guest_path.empty() || (!set_uid && !set_gid)) return;
    auto& rm = entries_[guest_path];
    if (set_uid) {
        rm.uid = uid;
        rm.has_uid = true;
    }
    if (set_gid) {
        rm.gid = gid;
        rm.has_gid = true;
    }
    append_set_line(guest_path, rm);
}

void RuntimeMetaStore::set_mode(const std::string& guest_path, uint32_t mode) {
    if (guest_path.empty()) return;
    auto& rm = entries_[guest_path];
    rm.mode = mode & 07777U;
    rm.has_mode = true;
    append_set_line(guest_path, rm);
}

void RuntimeMetaStore::record_created(const std::string& guest_path, uid_t uid, gid_t gid) {
    if (guest_path.empty()) return;
    auto& rm = entries_[guest_path];
    rm.uid = uid;
    rm.gid = gid;
    rm.has_uid = true;
    rm.has_gid = true;
    rm.has_mode = false;
    rm.mode = 0;
    append_set_line(guest_path, rm);
}

void RuntimeMetaStore::copy_meta(const std::string& src_guest_path, const std::string& dst_guest_path,
                                 const VfsMetaDb* meta_db, uid_t fallback_uid, gid_t fallback_gid) {
    if (dst_guest_path.empty()) return;
    RuntimeStatMeta rm;
    auto sit = entries_.find(src_guest_path);
    if (sit != entries_.end()) {
        rm = sit->second;
    } else if (meta_db != nullptr) {
        if (auto m = meta_db->find(src_guest_path); m.has_value()) {
            rm.uid = m->entry->uid;
            rm.gid = m->entry->gid;
            rm.has_uid = true;
            rm.has_gid = true;
        } else {
            rm.uid = fallback_uid;
            rm.gid = fallback_gid;
            rm.has_uid = true;
            rm.has_gid = true;
        }
    } else {
        rm.uid = fallback_uid;
        rm.gid = fallback_gid;
        rm.has_uid = true;
        rm.has_gid = true;
    }
    entries_[dst_guest_path] = rm;
    append_set_line(dst_guest_path, rm);
}

void RuntimeMetaStore::apply_rename_map(std::unordered_map<std::string, RuntimeStatMeta>& map,
                                        const std::string& old_path, const std::string& new_path,
                                        bool is_exchange) {
    if (old_path.empty() || new_path.empty() || old_path == new_path) return;

    std::vector<std::pair<std::string, RuntimeStatMeta>> moved_old;
    for (auto it = map.begin(); it != map.end();) {
        if (has_path_prefix(it->first, old_path)) {
            moved_old.emplace_back(it->first, it->second);
            it = map.erase(it);
        } else {
            ++it;
        }
    }

    std::vector<std::pair<std::string, RuntimeStatMeta>> moved_new;
    for (auto it = map.begin(); it != map.end();) {
        if (has_path_prefix(it->first, new_path)) {
            if (is_exchange) {
                moved_new.emplace_back(it->first, it->second);
            }
            it = map.erase(it);
        } else {
            ++it;
        }
    }

    for (auto& [k, v] : moved_old) {
        std::string dst = new_path + k.substr(old_path.size());
        map.emplace(std::move(dst), std::move(v));
    }
    if (is_exchange) {
        for (auto& [k, v] : moved_new) {
            std::string dst = old_path + k.substr(new_path.size());
            map.emplace(std::move(dst), std::move(v));
        }
    }
}

void RuntimeMetaStore::apply_erase_map(std::unordered_map<std::string, RuntimeStatMeta>& map,
                                       const std::string& path) {
    if (path.empty()) return;
    for (auto it = map.begin(); it != map.end();) {
        if (has_path_prefix(it->first, path)) {
            it = map.erase(it);
        } else {
            ++it;
        }
    }
}

void RuntimeMetaStore::rename_meta(const std::string& old_guest_path,
                                   const std::string& new_guest_path,
                                   bool is_exchange) {
    if (old_guest_path.empty() || new_guest_path.empty() || old_guest_path == new_guest_path) return;
    apply_rename_map(entries_, old_guest_path, new_guest_path, is_exchange);
    std::string line = "R\t" + escape_path(old_guest_path) + "\t" +
                       escape_path(new_guest_path) + (is_exchange ? "\t1\n" : "\t0\n");
    append_journal_line(line);
}

void RuntimeMetaStore::erase_meta(const std::string& guest_path) {
    if (guest_path.empty()) return;
    apply_erase_map(entries_, guest_path);
    std::string line = "D\t" + escape_path(guest_path) + "\n";
    append_journal_line(line);
}

gid_t RuntimeMetaStore::effective_created_gid(const std::string& guest_path, gid_t default_gid,
                                              const VfsMetaDb* meta_db) const {
    if (guest_path.size() <= 1) return default_gid;
    size_t slash = guest_path.rfind('/');
    if (slash == std::string::npos) return default_gid;
    std::string parent_guest = (slash == 0) ? "/" : guest_path.substr(0, slash);

    struct stat pst {};
    std::string host_parent = (parent_guest == "/") ? rootfs_root_ : (rootfs_root_ + parent_guest);
    bool host_ok = (::lstat(host_parent.c_str(), &pst) == 0);

    bool has_setgid = host_ok && ((pst.st_mode & S_ISGID) != 0);
    const RuntimeStatMeta* pm = find(parent_guest);
    if (pm && pm->has_mode) {
        has_setgid = (pm->mode & S_ISGID) != 0;
    } else if (!has_setgid && meta_db != nullptr) {
        if (auto m = meta_db->find(parent_guest); m.has_value()) {
            has_setgid = (m->entry->mode & S_ISGID) != 0;
        }
    }

    if (!has_setgid) return default_gid;
    if (pm && pm->has_gid) return pm->gid;
    if (meta_db != nullptr) {
        if (auto m = meta_db->find(parent_guest); m.has_value()) {
            return m->entry->gid;
        }
    }
    return default_gid;
}

}  // namespace vguest
