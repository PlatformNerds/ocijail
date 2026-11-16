// Unit tests for sysctl::from_oci_sysctl (pure translation, no syscalls).
#include <cstdlib>
#include <iostream>

#include "ocijail/sysctl.h"

using nlohmann::json;
using ocijail::sysctl::from_oci_sysctl;
using settings = std::vector<std::pair<std::string, int>>;

static void expect(const json& in, settings want,
                   std::vector<std::string> ignored = {}) {
    auto t = from_oci_sysctl(in);
    if (t.settings != want || t.ignored != ignored) {
        std::cerr << "FAIL for " << in.dump() << "\n  got:";
        for (auto& [k, v] : t.settings) std::cerr << " " << k << "=" << v;
        std::cerr << "\n  ignored:";
        for (auto& i : t.ignored) std::cerr << " " << i;
        std::cerr << "\n";
        std::exit(1);
    }
}

int main() {
    const std::string rh = "net.inet.ip.portrange.reservedhigh";
    expect(json::object(), {});
    expect(json(nullptr), {});
    expect({{"net.ipv4.ip_unprivileged_port_start", "0"}}, {{rh, 0}});
    expect({{"net.ipv4.ip_unprivileged_port_start", "1"}}, {{rh, 0}});
    expect({{"net.ipv4.ip_unprivileged_port_start", "1024"}}, {{rh, 1023}});
    expect({{"net.ipv4.ip_unprivileged_port_start", "80x"}}, {},
           {"net.ipv4.ip_unprivileged_port_start=80x"});
    expect({{"net.ipv4.ip_unprivileged_port_start", "-1"}}, {},
           {"net.ipv4.ip_unprivileged_port_start=-1"});
    expect({{"net.ipv4.ip_local_port_range", "32768 60999"}},
           {{"net.inet.ip.portrange.first", 32768},
            {"net.inet.ip.portrange.last", 60999}});
    expect({{"net.ipv4.ip_local_port_range", "2000\t3000"}},
           {{"net.inet.ip.portrange.first", 2000},
            {"net.inet.ip.portrange.last", 3000}});
    expect({{"net.ipv4.ip_local_port_range", "3000 2000"}}, {},
           {"net.ipv4.ip_local_port_range=3000 2000"});
    expect({{"net.ipv4.ip_local_port_range", "1 2 3"}}, {},
           {"net.ipv4.ip_local_port_range=1 2 3"});
    expect({{"kernel.shm_rmid_forced", "1"}}, {}, {"kernel.shm_rmid_forced=1"});
    std::cout << "sysctl_test: PASS\n";
    return 0;
}
