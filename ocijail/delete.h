#pragma once

#include <optional>

#include "ocijail/main.h"

namespace ocijail {

// Release what a stopped container holds on the host: remove its jail (killing
// any processes left in it, as a Linux PID namespace does when its init exits)
// and unmount its volumes, so that e.g. the kubelet can tear down a pod's
// volumes as soon as its containers have stopped instead of waiting for the
// container to be deleted. Idempotent; delete() calls it too.
void release_stopped_container(main_app& app, runtime_state& state);

struct delete_ {
    static void init(main_app& app);

   private:
    delete_(main_app& app);
    void run();

    main_app& app_;
    bool force_{false};
    std::string id_;
};

}  // namespace ocijail
