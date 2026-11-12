#include "capability/capability.hpp"
#include "model/run_config.hpp"

#include <algorithm>
#include <cerrno>
#include <charconv>
#include <cstring>
#include <fstream>
#include <optional>
#include <sched.h>
#include <set>
#include <sstream>
#include <stdexcept>
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
std::string cpu_path(int cpu) {
    return "/sys/devices/system/cpu/cpu" + std::to_string(cpu);
}

std::optional<int> parse_int(const std::string& text) {
    int value = 0;
    const auto* begin = text.data();
    const auto* end = begin + text.size();
    const auto parsed = std::from_chars(begin, end, value);
    if (parsed.ec != std::errc{} || parsed.ptr != end)
        return std::nullopt;
    return value;
}

std::optional<std::set<int>> parse_cpu_list(const std::string& text) {
    if (text.empty())
        return std::nullopt;
    std::set<int> cpus;
    std::size_t begin = 0;
    while (begin < text.size()) {
        const auto comma = text.find(',', begin);
        const auto token = text.substr(begin, comma == std::string::npos ? comma : comma - begin);
        const auto dash = token.find('-');
        const auto first = parse_int(token.substr(0, dash));
        const auto last = dash == std::string::npos ? first : parse_int(token.substr(dash + 1));
        if (!first || !last || *first < 0 || *last < *first)
            return std::nullopt;
        for (int cpu = *first; cpu <= *last; ++cpu)
            cpus.insert(cpu);
        if (comma == std::string::npos)
            break;
        begin = comma + 1;
    }
    return cpus;
}

model::CpuTopology inspect_cpu_topology(int cpu, const std::optional<std::set<int>>& online_cpus) {
    model::CpuTopology topology;
    topology.cpu = cpu;
    const auto path = cpu_path(cpu) + "/topology/";
    const auto package = parse_int(read_line(path + "physical_package_id"));
    const auto core = parse_int(read_line(path + "core_id"));
    if (package && *package >= 0)
        topology.package_id = package;
    if (core && *core >= 0)
        topology.core_id = core;

    const auto siblings = parse_cpu_list(read_line(path + "thread_siblings_list"));
    if (siblings) {
        topology.thread_siblings.emplace();
        for (const int sibling : *siblings) {
            model::CpuSibling value;
            value.cpu = sibling;
            if (online_cpus)
                value.online = online_cpus->contains(sibling);
            topology.thread_siblings->push_back(value);
        }
    }
    return topology;
}

const model::CpuTopology* find_topology(const model::Environment& environment, int cpu) {
    const auto found =
        std::find_if(environment.cpu_topology.begin(), environment.cpu_topology.end(),
                     [cpu](const auto& topology) { return topology.cpu == cpu; });
    return found == environment.cpu_topology.end() ? nullptr : &*found;
}

} // namespace

std::string stable_environment_hash(const model::Environment& environment) {
    std::ostringstream identity;
    identity << environment.kernel << '\n'
             << environment.cpu_model << '\n'
             << environment.compiler << '\n'
             << environment.governor << '\n'
             << environment.boost << '\n'
             << environment.wsl << '\n'
             << "perf_event_paranoid:";
    if (environment.perf_event_paranoid)
        identity << *environment.perf_event_paranoid;
    else
        identity << "unknown";
    for (const auto cpu : environment.allowed_cpus)
        identity << "\nallowed:" << cpu;
    for (const auto cpu : environment.physical_cpus)
        identity << "\nphysical:" << cpu;
    for (const auto& topology : environment.cpu_topology) {
        identity << "\ntopology:" << topology.cpu << ':';
        if (topology.package_id)
            identity << *topology.package_id;
        else
            identity << "unknown";
        identity << ':';
        if (topology.core_id)
            identity << *topology.core_id;
        else
            identity << "unknown";
        identity << ":siblings=";
        if (!topology.thread_siblings) {
            identity << "unknown";
            continue;
        }
        for (const auto& sibling : *topology.thread_siblings) {
            identity << sibling.cpu << '/';
            if (sibling.online)
                identity << (*sibling.online ? "online" : "offline");
            else
                identity << "unknown";
            identity << ',';
        }
    }
    return model::fingerprint(identity.str());
}

model::Environment inspect_environment() {
    model::Environment environment;
    utsname system{};
    if (uname(&system) == 0)
        environment.kernel = std::string(system.sysname) + " " + system.release;
    environment.wsl = environment.kernel.find("microsoft") != std::string::npos ||
                      environment.kernel.find("Microsoft") != std::string::npos;
    environment.compiler = model::build_information();
    const auto paranoid = read_line("/proc/sys/kernel/perf_event_paranoid");
    environment.perf_event_paranoid = parse_int(paranoid);
    if (!environment.perf_event_paranoid)
        environment.perf_event_paranoid_reason = paranoid.empty()
                                                     ? "perf_event_paranoid is unavailable"
                                                     : "perf_event_paranoid is not an integer";
    std::ifstream cpuinfo("/proc/cpuinfo");
    for (std::string line; std::getline(cpuinfo, line);) {
        if (line.starts_with("model name") || line.starts_with("Hardware")) {
            const auto colon = line.find(':');
            if (colon != std::string::npos)
                environment.cpu_model = line.substr(colon + 1);
            break;
        }
    }
    cpu_set_t allowed;
    CPU_ZERO(&allowed);
    if (sched_getaffinity(0, sizeof(allowed), &allowed) == 0) {
        std::set<std::string> cores;
        std::set<std::string> governors;
        bool unknown_topology = false;
        const auto online_cpus = parse_cpu_list(read_line("/sys/devices/system/cpu/online"));
        for (int cpu = 0; cpu < CPU_SETSIZE; ++cpu) {
            if (!CPU_ISSET(cpu, &allowed))
                continue;
            environment.allowed_cpus.push_back(cpu);
            auto topology = inspect_cpu_topology(cpu, online_cpus);
            const auto key =
                topology.package_id && topology.core_id
                    ? std::to_string(*topology.package_id) + ":" + std::to_string(*topology.core_id)
                    : std::string{};
            environment.cpu_topology.push_back(std::move(topology));
            if (key.empty())
                unknown_topology = true;
            else if (cores.insert(key).second)
                environment.physical_cpus.push_back(cpu);
            auto governor = read_line(cpu_path(cpu) + "/cpufreq/scaling_governor");
            governors.insert(governor.empty() ? "unknown" : governor);
        }
        for (const auto& governor : governors) {
            if (!environment.governor.empty())
                environment.governor += ",";
            environment.governor += governor;
        }
        if (unknown_topology)
            environment.warnings.push_back("Some physical core identities are unavailable");
    } else
        environment.warnings.push_back(std::string("CPU affinity inspection failed: ") +
                                       std::strerror(errno));
    const auto boost = read_line("/sys/devices/system/cpu/cpufreq/boost");
    const auto no_turbo = read_line("/sys/devices/system/cpu/intel_pstate/no_turbo");
    if (!boost.empty())
        environment.boost = boost == "0" ? "disabled" : "enabled";
    else if (!no_turbo.empty())
        environment.boost = no_turbo == "1" ? "disabled" : "enabled";
    else
        environment.boost = "unknown";
    if (environment.governor != "performance")
        environment.warnings.push_back(
            "CPU frequency governor is not uniformly verified as performance");
    if (environment.boost != "disabled")
        environment.warnings.push_back("CPU boost is not verified disabled");
    if (getloadavg(&environment.load_before, 1) != 1)
        environment.warnings.push_back("Load average unavailable");
    if (environment.wsl)
        environment.warnings.push_back("WSL environment; do not combine with native Linux results");
    environment.warnings.push_back(
        "Clock synchronization and competing machine load are not controlled");
    environment.environment_hash = stable_environment_hash(environment);
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
    if (!config.pin_cores) {
        config.cpu = -1;
        return;
    }
    if (config.cpu < 0 && !environment.allowed_cpus.empty())
        config.cpu = environment.allowed_cpus.front();
    if (std::find(environment.allowed_cpus.begin(), environment.allowed_cpus.end(), config.cpu) ==
        environment.allowed_cpus.end())
        throw std::runtime_error("Requested endpoint CPU is not allowed");
}

std::vector<std::string> cpu_selection_warnings(const model::RunConfig& config,
                                                const model::Environment& environment) {
    if (!config.pin_cores)
        return {"CPU affinity is disabled; role placement is not verified"};

    std::vector<std::string> warnings;
    const auto role = std::string(model::name(config.role));
    const int cpu = config.cpu;
    const auto* topology = find_topology(environment, cpu);
    if (cpu < 0)
        warnings.push_back(role + " CPU placement is not verified");
    else if (!topology || !topology->package_id || !topology->core_id)
        warnings.push_back(role + " CPU physical core is not verified");
    else if (!topology->thread_siblings)
        warnings.push_back(
            role + " CPU thread siblings are unknown; exclusive core use is not guaranteed");
    else {
        for (const auto& sibling : *topology->thread_siblings) {
            if (sibling.cpu == cpu || sibling.online == false)
                continue;
            const bool allowed =
                std::find(environment.allowed_cpus.begin(), environment.allowed_cpus.end(),
                          sibling.cpu) != environment.allowed_cpus.end();
            auto warning =
                role + " CPU shares its physical core with CPU " + std::to_string(sibling.cpu);
            if (!allowed)
                warning += " outside the allowed affinity mask";
            if (!sibling.online)
                warning += "; sibling online state is unknown";
            warning += "; sibling idleness is unverified and exclusive core use is not guaranteed";
            warnings.push_back(std::move(warning));
        }
    }
    if (environment.wsl)
        warnings.push_back(
            "WSL CPU topology is guest-visible and does not prove physical host dedication");
    warnings.push_back(
        "CPU affinity and topology are inspected during setup; whole-run exclusive use is not "
        "guaranteed");
    return warnings;
}
} // namespace turtle::capability
