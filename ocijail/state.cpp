#include <signal.h>
#include <iostream>

#include "nlohmann/json.hpp"

#include "delete.h"
#include "state.h"

namespace fs = std::filesystem;

using nlohmann::json;

namespace ocijail {

void state::init(main_app& app) {
    static state instance{app};
}

state::state(main_app& app) : app_(app) {
    auto sub = app.add_subcommand(
        "state", "Get the state of the container with the given id");
    sub->add_option("container-id", id_, "Unique identifier for the container")
        ->required();
    sub->final_callback([this] { run(); });
}

void state::run() {
    auto state = app_.get_runtime_state(id_);
    auto lk = state.lock();
    state.load();

    // update state
    state.check_status();

    // Once stopped, release the container's jail and volumes right away
    // (see release_stopped_container). Failing here must not hide the state:
    // the release is retried on the next query and by delete.
    if (state["status"] == "stopped") {
        try {
            release_stopped_container(app_, state);
        } catch (const std::exception& e) {
            app_.log() << "releasing stopped container " << id_ << ": "
                       << e.what();
        }
    }

    std::cout << state.report();
}

}  // namespace ocijail
