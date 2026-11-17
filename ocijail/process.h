#pragma once

#include "nlohmann/json.hpp"

#include "ocijail/main.h"

namespace ocijail {

struct process {
    // initialise with a json from either create or exec - this will
    // validate the input, throwing an error if necessary.
    process(const nlohmann::json& process,
            std::optional<std::filesystem::path> console_socket,
            bool detach,
            int preserve_fds);

    // Like std::getenv but using the env list from this process
    std::optional<std::string_view> getenv(std::string_view key);

    // Like setenv but using the env list from this process
    void setenv(std::string_view key, std::string_view val);

    // Validate the command and throw an error if its not found
    void validate();

    // Call this before start - return value is three file descriptors for
    // stdin, stdout, stderr
    std::tuple<int, int, int> pre_start();
    void exec(int stdin_fd, int stdout_fd, int stderr_fd);

   private:
    void reset_signals();
    void set_uid_gid();
    void set_no_new_privs();
    // Add a KEY=value entry to env_. A later entry for the same KEY
    // replaces the earlier value in place, which matches runc (it
    // applies process.env with setenv in order).
    void add_env(std::string keyval);

    std::optional<std::filesystem::path> console_socket_;
    bool detach_;
    int preserve_fds_;

    // Copied out from the json during parsing
    std::string cwd_;
    std::vector<std::string> args_;
    std::vector<std::string> env_;
    std::vector<gid_t> gids_;
    uid_t uid_;
    gid_t gid_;
    std::optional<mode_t> umask_;
    bool terminal_{false};
    bool no_new_privs_{false};
};

}  // namespace ocijail
