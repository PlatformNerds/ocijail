#pragma once

#include <string>
#include <utility>
#include <vector>

#include "nlohmann/json.hpp"

namespace ocijail::sysctl {

// Translate OCI "linux.sysctl" entries into FreeBSD sysctls that are
// per-VNET, so they can be set inside a pod's own vnet jail without
// touching the host. Pure function, no syscalls, so it can be unit tested.
//
//   net.ipv4.ip_unprivileged_port_start=N
//       -> net.inet.ip.portrange.reservedhigh=max(N-1, 0)
//          Ports up to reservedhigh need privilege to bind; 0 lets any user
//          bind any port, like Linux with ip_unprivileged_port_start=0 (the
//          containerd 2.x default for pods). Covers IPv4 and IPv6.
//   net.ipv4.ip_local_port_range="LOW HIGH"
//       -> net.inet.ip.portrange.first=LOW, net.inet.ip.portrange.last=HIGH
//
// Anything else is returned in "ignored" (Linux-only, or not per-VNET).
struct translation {
    std::vector<std::pair<std::string, int>> settings;
    std::vector<std::string> ignored;
};

translation from_oci_sysctl(const nlohmann::json& sysctls);

// Set the given sysctls from inside the jail (fork, jail_attach,
// sysctlbyname). The jail must own its vnet for the kernel to allow it.
void apply_in_jail(int jid, const translation& t);

}  // namespace ocijail::sysctl
