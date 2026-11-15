#include "ocijail/rctl.h"

#include <sys/types.h>
#include <sys/rctl.h>

#include <cerrno>
#include <cstdint>
#include <string_view>
#include <system_error>
#include <vector>

using nlohmann::json;

namespace ocijail::rctl {

namespace {

// Returns the value of an integer field if present, non-null and > 0.
std::optional<std::int64_t> positive(const json& obj, const char* key) {
    if (!obj.is_object() || !obj.contains(key) || !obj[key].is_number_integer()) {
        return std::nullopt;
    }
    auto v = obj[key].get<std::int64_t>();
    if (v <= 0) {
        return std::nullopt;
    }
    return v;
}

}  // namespace

translation from_oci_resources(const json& resources) {
    translation t;
    if (!resources.is_object()) {
        return t;
    }

    if (resources.contains("memory")) {
        if (auto limit = positive(resources["memory"], "limit")) {
            t.rules.push_back("memoryuse:sigkill=" + std::to_string(*limit));
        }
    }

    if (resources.contains("cpu")) {
        const auto& cpu = resources["cpu"];
        auto quota = positive(cpu, "quota");
        auto period = positive(cpu, "period");
        if (quota && period) {
            // percent of one CPU, rounded up, at least 1
            auto pct = (*quota * 100 + *period - 1) / *period;
            t.rules.push_back("pcpu:deny=" + std::to_string(pct < 1 ? 1 : pct));
        }
        if (positive(cpu, "shares")) {
            t.ignored.push_back("cpu.shares");
        }
    }

    if (resources.contains("pids")) {
        if (auto limit = positive(resources["pids"], "limit")) {
            t.rules.push_back("maxproc:deny=" + std::to_string(*limit));
        }
    }

    return t;
}

json merge_oci_resources(const json& base, const json& update) {
    json merged = base.is_object() ? base : json::object();
    if (!update.is_object()) {
        return merged;
    }
    for (auto& [key, value] : update.items()) {
        if (value.is_null()) {
            continue;
        }
        if (value.is_object() && merged.contains(key) && merged[key].is_object()) {
            merged[key] = merge_oci_resources(merged[key], value);
        } else if (value.is_object()) {
            merged[key] = merge_oci_resources(json::object(), value);
        } else {
            merged[key] = value;
        }
    }
    return merged;
}

const std::vector<std::string> managed_keys = {
    "memoryuse:sigkill", "pcpu:deny", "maxproc:deny"};

bool replace(const std::string& jail_name, const std::vector<std::string>& rules) {
    for (const auto& key : managed_keys) {
        auto filter = "jail:" + jail_name + ":" + key;
        if (::rctl_remove_rule(filter.c_str(), filter.size() + 1, nullptr, 0) < 0) {
            if (errno == ENOSYS || errno == EPERM) {
                return false;
            }
            if (errno != ESRCH) {
                throw std::system_error(
                    errno, std::system_category(), "rctl_remove_rule " + filter);
            }
        }
    }
    return apply(jail_name, rules);
}

std::optional<std::int64_t> usage(const std::string& jail_name,
                                  const std::string& resource) {
    auto filter = "jail:" + jail_name;
    std::vector<char> buf(4096);
    for (;;) {
        if (::rctl_get_racct(filter.c_str(), filter.size() + 1, buf.data(),
                             buf.size()) == 0) {
            break;
        }
        if (errno == ERANGE && buf.size() < (1 << 20)) {
            buf.resize(buf.size() * 4);
            continue;
        }
        return std::nullopt;
    }
    // "cputime=0,datasize=1234,...,memoryuse=45400064,..."
    std::string_view s{buf.data()};
    auto prefix = resource + "=";
    for (size_t pos = 0; pos < s.size();) {
        auto end = s.find(',', pos);
        if (end == std::string_view::npos) {
            end = s.size();
        }
        auto item = s.substr(pos, end - pos);
        if (item.starts_with(prefix)) {
            try {
                return std::stoll(std::string{item.substr(prefix.size())});
            } catch (...) {
                return std::nullopt;
            }
        }
        pos = end + 1;
    }
    return std::nullopt;
}

bool apply(const std::string& jail_name, const std::vector<std::string>& rules) {
    for (const auto& r : rules) {
        auto rule = "jail:" + jail_name + ":" + r;
        if (::rctl_add_rule(rule.c_str(), rule.size() + 1, nullptr, 0) < 0) {
            if (errno == ENOSYS || errno == EPERM) {
                // ENOSYS: RACCT disabled (kern.racct.enable=0).
                // EPERM: not allowed here, e.g. ocijail running in a jail.
                return false;
            }
            throw std::system_error(
                errno, std::system_category(), "rctl_add_rule " + rule);
        }
    }
    return true;
}

void remove(const std::string& jail_name) {
    auto filter = "jail:" + jail_name;
    if (::rctl_remove_rule(filter.c_str(), filter.size() + 1, nullptr, 0) < 0) {
        if (errno == ENOSYS || errno == ESRCH || errno == EPERM) {
            return;  // no RACCT, no matching rules, or not permitted here
        }
        throw std::system_error(
            errno, std::system_category(), "rctl_remove_rule " + filter);
    }
}

}  // namespace ocijail::rctl
