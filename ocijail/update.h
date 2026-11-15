#pragma once

#include <optional>
#include <string>

#include "ocijail/main.h"

namespace ocijail {

// `update --resources <file|->`: change a running container's resource limits
// (OCI linux.resources, as runc update does). CRI-O uses this for the CRI
// UpdateContainerResources call, i.e. Kubernetes in-place pod resize.
struct update {
    static void init(main_app& app);

   private:
    update(main_app& app);
    void run();

    main_app& app_;
    std::string id_;
    std::string resources_;
};

}  // namespace ocijail
