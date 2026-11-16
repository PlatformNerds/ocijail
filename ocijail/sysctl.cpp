#include "ocijail/sysctl.h"

#include <sys/param.h>
#include <sys/jail.h>
#include <sys/sysctl.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <sstream>
#include <stdexcept>
#include <system_error>

namespace ocijail::sysctl {

static bool parse_int(const std::string& s, int& out) {
    if (s.empty()) {
        return false;
    }
    char* end = nullptr;
    errno = 0;
    long v = std::strtol(s.c_str(), &end, 10);
    if (errno != 0 || *end != '\0' || v < 0 || v > 65535) {
        return false;
    }
    out = static_cast<int>(v);
    return true;
}

translation from_oci_sysctl(const nlohmann::json& sysctls) {
    translation t;
    if (!sysctls.is_object()) {
        return t;
    }
    for (const auto& [key, val] : sysctls.items()) {
        std::string v = val.is_string() ? val.get<std::string>() : val.dump();
        if (key == "net.ipv4.ip_unprivileged_port_start") {
            int n;
            if (!parse_int(v, n)) {
                t.ignored.push_back(key + "=" + v);
                continue;
            }
            t.settings.emplace_back("net.inet.ip.portrange.reservedhigh",
                                    std::max(n - 1, 0));
        } else if (key == "net.ipv4.ip_local_port_range") {
            std::istringstream in(v);
            std::string lo_s, hi_s, extra;
            int lo, hi;
            if (!(in >> lo_s >> hi_s) || (in >> extra) || !parse_int(lo_s, lo) ||
                !parse_int(hi_s, hi) || lo == 0 || lo > hi) {
                t.ignored.push_back(key + "=" + v);
                continue;
            }
            t.settings.emplace_back("net.inet.ip.portrange.first", lo);
            t.settings.emplace_back("net.inet.ip.portrange.last", hi);
        } else {
            t.ignored.push_back(key + "=" + v);
        }
    }
    return t;
}

void apply_in_jail(int jid, const translation& t) {
    if (t.settings.empty()) {
        return;
    }
    int pipefd[2];
    if (::pipe(pipefd) < 0) {
        throw std::system_error{errno, std::system_category(), "pipe"};
    }
    pid_t pid = ::fork();
    if (pid < 0) {
        int e = errno;
        ::close(pipefd[0]);
        ::close(pipefd[1]);
        throw std::system_error{e, std::system_category(), "fork"};
    }
    if (pid == 0) {
        // Child: report the index of the failing setting and errno.
        ::close(pipefd[0]);
        int report[2] = {-1, 0};
        if (::jail_attach(jid) < 0) {
            report[1] = errno;
        } else {
            for (std::size_t i = 0; i < t.settings.size(); i++) {
                int v = t.settings[i].second;
                if (::sysctlbyname(t.settings[i].first.c_str(), nullptr,
                                   nullptr, &v, sizeof(v)) < 0) {
                    report[0] = static_cast<int>(i);
                    report[1] = errno;
                    break;
                }
            }
        }
        (void)!::write(pipefd[1], report, sizeof(report));
        ::_exit(report[1] == 0 ? 0 : 1);
    }
    ::close(pipefd[1]);
    int report[2] = {-1, 0};
    ssize_t n = ::read(pipefd[0], report, sizeof(report));
    ::close(pipefd[0]);
    int status = 0;
    while (::waitpid(pid, &status, 0) < 0 && errno == EINTR) {
    }
    if (n != sizeof(report)) {
        throw std::runtime_error("sysctl: helper process failed");
    }
    if (report[1] != 0) {
        std::string what = report[0] < 0
                               ? std::string{"jail_attach"}
                               : "setting " + t.settings[report[0]].first;
        throw std::system_error{report[1], std::system_category(),
                                "sysctl: " + what};
    }
}

}  // namespace ocijail::sysctl
