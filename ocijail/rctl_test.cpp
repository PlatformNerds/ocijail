// Unit tests for rctl::from_oci_resources (pure translation, no syscalls).
#include <cassert>
#include <cstdlib>
#include <iostream>

#include "ocijail/rctl.h"

using nlohmann::json;
using ocijail::rctl::from_oci_resources;
using ocijail::rctl::merge_oci_resources;

static void expect(const json& res, std::vector<std::string> rules,
                   std::vector<std::string> ignored = {}) {
    auto t = from_oci_resources(res);
    if (t.rules != rules || t.ignored != ignored) {
        std::cerr << "FAIL for " << res.dump() << "\n  got rules:";
        for (auto& r : t.rules) std::cerr << " " << r;
        std::cerr << "\n";
        std::exit(1);
    }
}

static void expect_merge(const char* base, const char* update, const char* want) {
    auto got = merge_oci_resources(json::parse(base), json::parse(update));
    if (got != json::parse(want)) {
        std::cerr << "FAIL merge " << base << " + " << update << "\n  got  " << got.dump()
                  << "\n  want " << want << "\n";
        std::exit(1);
    }
}

int main() {
    // update --resources: partial updates keep what they don't mention
    // (CRI-O sends cpu {quota, period, shares} and memory {limit} only when set)
    expect_merge(R"({"memory":{"limit":134217728},"cpu":{"quota":20000,"period":100000,"shares":102},"pids":{"limit":100}})",
                 R"({"memory":{"limit":268435456},"cpu":{}})",
                 R"({"memory":{"limit":268435456},"cpu":{"quota":20000,"period":100000,"shares":102},"pids":{"limit":100}})");
    expect_merge(R"({"cpu":{"quota":20000,"period":100000}})",
                 R"({"cpu":{"quota":50000,"cpus":""},"memory":{"limit":null}})",
                 R"({"cpu":{"quota":50000,"period":100000,"cpus":""},"memory":{}})");
    expect_merge("null", R"({"memory":{"limit":1048576}})", R"({"memory":{"limit":1048576}})");

    // nothing / not an object / empty
    expect(json(), {});
    expect(json::object(), {});
    // kubelet: limits {memory: 64Mi, cpu: 200m}, requests -> shares
    expect(json::parse(R"({"memory":{"limit":67108864},
                           "cpu":{"quota":20000,"period":100000,"shares":204}})"),
           {"memoryuse:sigkill=67108864", "pcpu:deny=20"},
           {"cpu.shares"});
    // >1 CPU and rounding up: 1.5 CPU, 333m
    expect(json::parse(R"({"cpu":{"quota":150000,"period":100000}})"), {"pcpu:deny=150"});
    expect(json::parse(R"({"cpu":{"quota":33300,"period":100000}})"), {"pcpu:deny=34"});
    // tiny quota still at least 1%
    expect(json::parse(R"({"cpu":{"quota":1,"period":100000}})"), {"pcpu:deny=1"});
    // unlimited markers are ignored: quota -1, limit 0, missing period
    expect(json::parse(R"({"cpu":{"quota":-1,"period":100000},"memory":{"limit":0}})"), {});
    expect(json::parse(R"({"cpu":{"quota":50000}})"), {});
    // pids
    expect(json::parse(R"({"pids":{"limit":4096}})"), {"maxproc:deny=4096"});
    // wrong types are ignored rather than crashing
    expect(json::parse(R"({"memory":{"limit":"64Mi"},"pids":{"limit":null}})"), {});
    std::cout << "rctl_test: all passed\n";
    return 0;
}
