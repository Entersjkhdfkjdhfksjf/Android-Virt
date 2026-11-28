#pragma once

#include <cstdint>
#include <string>
#include <sys/types.h>
#include <unordered_map>

#include "vfs_meta_format.hpp"

namespace vguest {

struct RuntimeStatMeta {
    uid_t uid = 0;
    gid_t gid = 0;
    uint32_t mode = 0;
    bool has_uid = false;
    bool has_gid = false;
    bool has_mode = false;
};

class RuntimeMetaStore {
public:
    RuntimeMetaStore() = default;
    ~RuntimeMetaStore();

    RuntimeMetaStore(const RuntimeMetaStore&) = delete;
    RuntimeMetaStore& operator=(const RuntimeMetaStore&) = delete;

    // Load persisted .vguest_runtime_meta journal, prune deleted paths,
    // seed default /data ownership and recover existing /data/data + /data/user_de
    // package trees from /data/system/packages.list (and packages.xml),
    // compact atomically, and open the append journal for runtime updates.
    bool open_and_seed(const std::string& rootfs_root, const VfsMetaDb* meta_db = nullptr);
    void close();

    const RuntimeStatMeta* find(const std::string& guest_path) const;

    void set_owner(const std::string& guest_path, uid_t uid, bool set_uid,
                   gid_t gid, bool set_gid);
    void set_mode(const std::string& guest_path, uint32_t mode);
    void record_created(const std::string& guest_path, uid_t uid, gid_t gid);
    void copy_meta(const std::string& src_guest_path, const std::string& dst_guest_path,
                   const VfsMetaDb* meta_db, uid_t fallback_uid, gid_t fallback_gid);
    void rename_meta(const std::string& old_guest_path, const std::string& new_guest_path,
                     bool is_exchange = false);
    void erase_meta(const std::string& guest_path);

    // Resolve GID for a newly created file/dir inside its parent directory,
    // honoring S_ISGID inheritance if the parent has setgid set.
    gid_t effective_created_gid(const std::string& guest_path, gid_t default_gid,
                                const VfsMetaDb* meta_db = nullptr) const;

    size_t size() const noexcept { return entries_.size(); }

    // Parse /data/system/packages.list and packages.xml into pkg -> base_uid.
    static std::unordered_map<std::string, uint32_t> load_package_uids(const std::string& rootfs_root);

private:
    static void parse_packages_list(const std::string& path,
                                    std::unordered_map<std::string, uint32_t>& out);
    static void parse_packages_xml(const std::string& path,
                                   std::unordered_map<std::string, uint32_t>& out);

    bool replay_journal(const std::string& journal_path);
    void prune_missing();
    void seed_aosp_data_defaults();
    void seed_system_dir_recursive(const std::string& guest_dir, const std::string& host_dir, int depth);
    void seed_package_data_trees(const std::unordered_map<std::string, uint32_t>& pkg_uids);
    void seed_pkg_subtree_recursive(const std::string& guest_base, const std::string& host_base,
                                    uint32_t uid, uint32_t normal_gid, uint32_t cache_gid,
                                    bool inside_cache, bool is_pkg_root, int depth);
    void seed_if_absent(const std::string& guest_path, uid_t uid, gid_t gid);
    bool compact_locked();
    void append_journal_line(const std::string& line);
    void append_set_line(const std::string& guest_path, const RuntimeStatMeta& meta);

    static void apply_rename_map(std::unordered_map<std::string, RuntimeStatMeta>& map,
                                 const std::string& old_path, const std::string& new_path,
                                 bool is_exchange);
    static void apply_erase_map(std::unordered_map<std::string, RuntimeStatMeta>& map,
                                const std::string& path);

    std::string rootfs_root_;
    std::string journal_path_;
    int journal_fd_ = -1;
    size_t journal_ops_ = 0;
    std::unordered_map<std::string, RuntimeStatMeta> entries_;
};

}  // namespace vguest
