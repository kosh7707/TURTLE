#include "capability/capability.hpp"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <set>
#include <sstream>
#include <stdexcept>
#include <sched.h>
#include <sys/utsname.h>
#include <unistd.h>

namespace turtle::capability {
namespace {
std::string read_line(const std::string& path) {
    std::ifstream input(path);
    std::string text;
    std::getline(input, text);
    return text;
}
std::string cpu_path(int cpu) { return "/sys/devices/system/cpu/cpu" + std::to_string(cpu); }
std::string core_key(int cpu) {
    const auto path = cpu_path(cpu) + "/topology/";
    const auto package = read_line(path + "physical_package_id");
    const auto core = read_line(path + "core_id");
    if (package.empty() || core.empty() || package == "-1" || core == "-1") return {};
    return package + ":" + core;
}
}
model::Environment inspect_environment() {
    model::Environment environment;
    utsname system{};
    if (uname(&system) == 0) environment.kernel = std::string(system.sysname) + " " + system.release;
    environment.wsl = environment.kernel.find("microsoft") != std::string::npos ||
                      environment.kernel.find("Microsoft") != std::string::npos;
    environment.compiler = __VERSION__;
    std::ifstream cpuinfo("/proc/cpuinfo");
    for (std::string line; std::getline(cpuinfo, line);) {
        if (line.starts_with("model name") || line.starts_with("Hardware")) {
            const auto colon = line.find(':');
            if (colon != std::string::npos) environment.cpu_model = line.substr(colon + 1);
            break;
        }
    }
    cpu_set_t allowed;
    CPU_ZERO(&allowed);
    if (sched_getaffinity(0, sizeof(allowed), &allowed) == 0) {
        std::set<std::string> cores;
        std::set<std::string> governors;
        bool unknown_topology = false;
        for (int cpu = 0; cpu < CPU_SETSIZE; ++cpu) {
            if (!CPU_ISSET(cpu, &allowed)) continue;
            environment.allowed_cpus.push_back(cpu);
            const auto key = core_key(cpu);
            if (key.empty()) unknown_topology = true;
            else if (cores.insert(key).second) environment.physical_cpus.push_back(cpu);
            auto governor = read_line(cpu_path(cpu) + "/cpufreq/scaling_governor");
            governors.insert(governor.empty() ? "unknown" : governor);
        }
        for (const auto& governor : governors) {
            if (!environment.governor.empty()) environment.governor += ",";
            environment.governor += governor;
        }
        if (unknown_topology) environment.warnings.push_back("Some physical core identities are unavailable");
    } else environment.warnings.push_back(std::string("CPU affinity inspection failed: ") + std::strerror(errno));
    const auto boost = read_line("/sys/devices/system/cpu/cpufreq/boost");
    const auto no_turbo = read_line("/sys/devices/system/cpu/intel_pstate/no_turbo");
    if (!boost.empty()) environment.boost = boost == "0" ? "disabled" : "enabled";
    else if (!no_turbo.empty()) environment.boost = no_turbo == "1" ? "disabled" : "enabled";
    else environment.boost = "unknown";
    if (environment.governor != "performance")
        environment.warnings.push_back("CPU frequency governor is not uniformly verified as performance");
    if (environment.boost != "disabled")
        environment.warnings.push_back("CPU boost is not verified disabled");
    if (getloadavg(&environment.load_before, 1) != 1)
        environment.warnings.push_back("Load average unavailable");
    if (environment.wsl) environment.warnings.push_back("WSL environment; do not combine with native Linux results");
    environment.warnings.push_back("Clock synchronization and competing machine load are not controlled");
    std::ostringstream identity;
    identity << environment.kernel << '\n' << environment.cpu_model << '\n' << environment.compiler
             << '\n' << environment.governor << '\n' << environment.boost << '\n' << environment.wsl;
    for (const auto cpu : environment.allowed_cpus) identity << "\nallowed:" << cpu;
    for (const auto cpu : environment.physical_cpus) identity << "\nphysical:" << cpu;
    environment.environment_hash = model::fingerprint(identity.str());
    return environment;
}
bool pin_to_cpu(int cpu, std::string& explanation) {
    if (cpu < 0 || cpu >= CPU_SETSIZE) {
        explanation = "CPU number is outside the supported affinity mask";
        return false;
    }
    cpu_set_t available;
    CPU_ZERO(&available);
    if (sched_getaffinity(0, sizeof(available), &available) != 0) {
        explanation = std::string("Cannot inspect affinity: ") + std::strerror(errno);
        return false;
    }
    if (!CPU_ISSET(cpu, &available)) {
        explanation = "Requested CPU is outside the current allowed affinity mask";
        return false;
    }
    cpu_set_t selected;
    CPU_ZERO(&selected);
    CPU_SET(cpu, &selected);
    if (sched_setaffinity(0, sizeof(selected), &selected) != 0) {
        explanation = std::string("Cannot pin CPU: ") + std::strerror(errno);
        return false;
    }
    explanation = "Pinned to CPU " + std::to_string(cpu);
    return true;
}
void choose_cpus(model::RunConfig& config, const model::Environment& environment) {
    if (!config.pin_cores) return;
    // Select only verified representatives. Explicit sibling CPUs are accepted
    // when their physical identity can be checked against the other selections.
    std::set<std::string> used;
    auto key = [&](int cpu) {
        auto physical = core_key(cpu);
        if (physical.empty() &&
            std::find(environment.physical_cpus.begin(), environment.physical_cpus.end(), cpu) != environment.physical_cpus.end())
            physical = "verified:" + std::to_string(cpu);
        return physical;
    };
    int selected[] = {config.director_cpu, config.client_cpu, config.server_cpu};
    for (const int cpu : selected) {
        if (cpu < 0) continue;
        if (std::find(environment.allowed_cpus.begin(), environment.allowed_cpus.end(), cpu) == environment.allowed_cpus.end())
            throw std::runtime_error("Requested CPU is not allowed");
        const auto physical = key(cpu);
        if (physical.empty() || !used.insert(physical).second)
            throw std::runtime_error("Requested CPUs must have distinct verified physical cores");
    }
    for (int& cpu : selected) {
        if (cpu >= 0) continue;
        for (const int candidate : environment.physical_cpus) {
            if (std::find(environment.allowed_cpus.begin(), environment.allowed_cpus.end(), candidate) == environment.allowed_cpus.end()) continue;
            const auto physical = key(candidate);
            if (!physical.empty() && used.insert(physical).second) { cpu = candidate; break; }
        }
        if (cpu < 0) throw std::runtime_error("Three distinct physical cores are unavailable; explicitly disable affinity to proceed");
    }
    config.director_cpu = selected[0];
    config.client_cpu = selected[1];
    config.server_cpu = selected[2];
}
}  // namespace turtle::capability
