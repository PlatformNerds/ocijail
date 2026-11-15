#include <fstream>
#include <iostream>
#include <iterator>
#include <sstream>

#include "nlohmann/json.hpp"

#include "ocijail/rctl.h"
#include "ocijail/update.h"

using nlohmann::json;

namespace ocijail {

void update::init(main_app& app) {
    static update instance{app};
}

update::update(main_app& app) : app_(app) {
    auto sub = app.add_subcommand(
        "update", "Update the resource limits of a container");
    sub->add_option("container-id", id_, "Unique identifier for the container")
        ->required();
    sub->add_option("--resources,-r",
                    resources_,
                    "Path to a JSON file with the new OCI linux.resources, "
                    "or - for standard input")
        ->required();
    sub->final_callback([this] { run(); });
}

void update::run() {
    json res;
    try {
        if (resources_ == "-") {
            res = json::parse(std::cin);
        } else {
            std::ifstream f{resources_};
            if (!f) {
                throw std::runtime_error("cannot open " + resources_);
            }
            res = json::parse(f);
        }
    } catch (const json::exception& e) {
        throw std::runtime_error(std::string{"update: invalid resources: "} +
                                 e.what());
    }
    if (!res.is_object()) {
        throw std::runtime_error("update: resources must be a JSON object");
    }

    auto state = app_.get_runtime_state(id_);
    auto lk = state.lock();
    state.load();
    state.check_status();
    if (state["status"] != "created" && state["status"] != "running") {
        std::stringstream ss;
        ss << "update: container not in \"created\" or \"running\" state "
              "(currently "
           << state["status"] << ")";
        throw std::runtime_error(ss.str());
    }
    auto jail_name = state["jail_name"].get<std::string>();

    auto& config = state["config"];
    json current = json::object();
    if (config.contains("linux") && config["linux"].contains("resources")) {
        current = config["linux"]["resources"];
    }
    auto merged = rctl::merge_oci_resources(current, res);
    auto t = rctl::from_oci_resources(merged);
    for (const auto& ign : t.ignored) {
        app_.log_debug() << "resource " << ign
                         << " is not supported on FreeBSD, ignoring";
    }

    // Like Linux (the kernel refuses a memory.max below usage with EBUSY),
    // refuse to lower the memory limit below what the container uses now:
    // memoryuse:sigkill would kill it instead. Best effort: racctd samples
    // memoryuse once per second, so a container started less than a second
    // ago may still report 0.
    if (merged.contains("memory") && merged["memory"].contains("limit") &&
        merged["memory"]["limit"].is_number_integer()) {
        auto limit = merged["memory"]["limit"].get<std::int64_t>();
        if (limit > 0) {
            if (auto used = rctl::usage(jail_name, "memoryuse");
                used && *used > limit) {
                std::stringstream ss;
                ss << "update: memory limit " << limit
                   << " is below the container's current usage " << *used;
                throw std::runtime_error(ss.str());
            }
        }
    }

    if (!rctl::replace(jail_name, t.rules) && !t.rules.empty()) {
        app_.log() << "warning: rctl unavailable (kern.racct.enable=0, or not "
                      "permitted in this jail), resource limits not enforced "
                      "for " << jail_name;
    }

    config["linux"]["resources"] = merged;
    state.save();
}

}  // namespace ocijail
