#include "config/config.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <unistd.h>

namespace {
void require(bool condition, const char* reason) {
    if (!condition)
        throw std::runtime_error(reason);
}
turtle::config::Command parse(std::initializer_list<std::string> options) {
    std::vector<std::string> strings(options);
    std::vector<char*> argv;
    for (auto& string : strings)
        argv.push_back(string.data());
    return turtle::config::parse(static_cast<int>(argv.size()), argv.data());
}
bool rejects(std::initializer_list<std::string> options) {
    try {
        (void)parse(options);
    } catch (const std::invalid_argument&) {
        return true;
    }
    return false;
}
} // namespace
int main() {
    const auto dir =
        std::filesystem::temp_directory_path() / ("turtle-config-" + std::to_string(getpid()));
    try {
        std::filesystem::create_directory(dir);
        const auto path = (dir / "profile.json").string();
        std::ofstream(path)
            << R"({"name":"test","pki":"certs","tls":{"tickets":0,"mutual_auth":true},"measurement":{"samples":3,"connections":2}})";
        const auto a = parse({"turtle", "run", "--samples", "7", "--connections", "3", "--profile",
                              path, "--no-perf"})
                           .run;
        require(a.samples == 7 && a.connections == 3 && a.tls.mutual_auth && !a.perf,
                "CLI must override profile independent of order");
        require(a.tls.ca_file == (dir / "certs/ca.pem").string(),
                "credential path must be profile-relative");
        const auto b = parse({"turtle", "run", "--profile", path, "--samples", "9"}).run;
        require(b.connections == 2, "profile connection count was not applied");
        require(a.profile_hash == b.profile_hash,
                "measurement settings must not fragment profile identity");
        const auto c = parse({"turtle", "run", "--profile", path, "--tickets", "2"}).run;
        require(c.profile_hash != b.profile_hash, "TLS changes must affect profile identity");
        std::filesystem::create_directory(dir / "certs");
        std::ofstream(dir / "certs/ca.pem") << "first test certificate input";
        const auto first_input = parse({"turtle", "run", "--profile", path}).run.profile_hash;
        std::ofstream(dir / "certs/ca.pem") << "different test certificate input";
        require(parse({"turtle", "run", "--profile", path}).run.profile_hash != first_input,
                "different certificate bytes must affect profile identity");
        require(parse({"turtle", "--help"}).action == turtle::config::Command::Action::Help,
                "help action");
        require(parse({"turtle", "capabilities"}).action ==
                    turtle::config::Command::Action::Capabilities,
                "capabilities action");
        require(parse({"turtle", "run"}).run.connections == 1, "default connection count changed");
        const auto profiles =
            std::filesystem::path(__FILE__).parent_path().parent_path().parent_path() /
            "examples/profiles";
        const auto repeated_profile = (profiles / "repeated-context.json").string();
        const auto repeated = parse({"turtle", "run", "--profile", repeated_profile}).run;
        const auto standard =
            parse({"turtle", "run", "--profile", (profiles / "server-auth.json").string()}).run;
        require(repeated.connections == 16 && repeated.warmups == 0 && repeated.timeout_ms == 30000,
                "repeated-context pilot settings were not parsed");
        require(repeated.tls.cipher == standard.tls.cipher &&
                    repeated.tls.group == standard.tls.group &&
                    repeated.tls.signature == standard.tls.signature &&
                    repeated.tls.ca_file == standard.tls.ca_file &&
                    repeated.tls.server_certificate == standard.tls.server_certificate &&
                    repeated.tls.server_key == standard.tls.server_key &&
                    repeated.tls.mutual_auth == standard.tls.mutual_auth &&
                    repeated.tls.tickets == standard.tls.tickets &&
                    repeated.tls.framework_io == standard.tls.framework_io &&
                    repeated.tls.application_bytes == standard.tls.application_bytes &&
                    !repeated.lookup.enabled,
                "repeated-context pilot changed the standard TLS workload");
        require(parse({"turtle", "run", "--profile", repeated_profile, "--connections", "4"})
                        .run.connections == 4,
                "explicit connection count did not override the pilot profile");
        require(parse({"turtle", "run"}).run.channel_observer,
                "channel observer default must remain enabled");
        const auto defaults = parse({"turtle", "run"}).run;
        require(!defaults.tx_timestamps && !defaults.cpu_profile,
                "diagnostic instrumentation must be opt-in");
        const auto profiled = parse({"turtle", "run", "--cpu-profile"}).run;
        require(profiled.cpu_profile && profiled.profile_hash == defaults.profile_hash,
                "CPU sampling marker changed the TLS workload identity");
        require(rejects({"turtle", "run", "--cpu-profile", "--mode", "trace"}) &&
                    rejects({"turtle", "run", "--cpu-profile", "--mode", "memory"}),
                "CPU sampling was mixed with another diagnostic mode");
        require(rejects({"turtle", "run", "--tx-timestamps"}) &&
                    rejects({"turtle", "run", "--tx-timestamps", "--mode", "trace", "--native-io"}),
                "TX timestamps accepted an unobserved transport");
        require(parse({"turtle", "run", "--tx-timestamps", "--mode", "trace"}).run.tx_timestamps,
                "TX timestamp option was not applied");
        const auto diagnostic_path = (dir / "diagnostic-profile.json").string();
        std::ofstream(diagnostic_path) << R"({"measurement":{"cpu_profile":true}})";
        require(parse({"turtle", "run", "--profile", diagnostic_path}).run.cpu_profile,
                "profile CPU sampling marker was not applied");
        std::ofstream(diagnostic_path)
            << R"({"measurement":{"mode":"trace","tx_timestamps":true}})";
        require(parse({"turtle", "run", "--profile", diagnostic_path}).run.tx_timestamps,
                "profile TX timestamp option was not applied");
        std::ofstream(diagnostic_path)
            << R"({"measurement":{"mode":"trace","tx_timestamps":true,"channel_observer":false}})";
        require(rejects({"turtle", "run", "--profile", diagnostic_path}),
                "TX timestamps accepted a disabled channel observer");
        std::ofstream(diagnostic_path)
            << R"({"lookup":{"enabled":true},"measurement":{"cpu_profile":true}})";
        require(rejects({"turtle", "run", "--profile", diagnostic_path}),
                "TLS-only profiler accepted a lookup run");
        require(parse({"turtle", "run"}).run.perf_scope == turtle::model::PerfScope::User,
                "perf scope default must remain user");
        const auto perf_scope_path = (dir / "perf-scope-profile.json").string();
        std::ofstream(perf_scope_path)
            << R"({"measurement":{"perf":true,"perf_scope":"user+kernel"}})";
        require(parse({"turtle", "run", "--profile", perf_scope_path}).run.perf_scope ==
                    turtle::model::PerfScope::UserKernel,
                "user+kernel perf scope was not applied");
        std::ofstream(perf_scope_path)
            << R"({"measurement":{"perf":false,"perf_scope":"user+kernel"}})";
        require(rejects({"turtle", "run", "--profile", perf_scope_path}),
                "disabled perf accepted a kernel-inclusive scope");
        std::ofstream(perf_scope_path) << R"({"measurement":{"perf_scope":"system"}})";
        require(rejects({"turtle", "run", "--profile", perf_scope_path}),
                "unknown perf scope was accepted");
        const auto observer_path = (dir / "observer-profile.json").string();
        std::ofstream(observer_path) << R"({"measurement":{"channel_observer":false}})";
        const auto observer_off = parse({"turtle", "run", "--profile", observer_path}).run;
        require(!observer_off.channel_observer,
                "measurement.channel_observer=false was not applied");
        require(observer_off.profile_hash == parse({"turtle", "run"}).run.profile_hash,
                "observer execution setting must not fragment TLS profile identity");
        require(
            parse({"turtle", "run", "--warmups", "1024", "--connections", "1"}).run.connections ==
                1,
            "maximum combined connection count was rejected");
        require(turtle::config::usage().find("--connections N") != std::string::npos &&
                    turtle::config::usage().find("Warm-up connections") != std::string::npos,
                "help does not distinguish measured and warm-up connections");
        require(rejects({"turtle", "run", "--samples", "-1"}), "negative sample count accepted");
        require(rejects({"turtle", "run", "--connections", "0"}),
                "zero measured connections accepted");
        require(rejects({"turtle", "run", "--connections", "1026"}),
                "too many measured connections accepted");
        require(rejects({"turtle", "run", "--warmups", "1024", "--connections", "2"}),
                "too many combined connections accepted");
        require(parse({"turtle", "run"}).run.tls.cipher == "TLS_AES_128_GCM_SHA256",
                "fixed cipher suite default changed");
        require(parse({"turtle", "run", "--cipher", "TLS_AES_128_GCM_SHA256"}).run.tls.cipher ==
                    "TLS_AES_128_GCM_SHA256",
                "fixed cipher suite was rejected");

        const auto lookup_path = (dir / "lookup-profile.json").string();
        std::ofstream(lookup_path)
            << R"({"tls":{"server_certificate":"certs/server-chain.pem"},)"
               R"("lookup":{"enabled":true,"object_file":"objects/chain.pem",)"
               R"("cache_mode":"fixed-snapshot","snapshot_file":"cache/warm.json"},)"
               R"("measurement":{"samples":4,"failure_policy":"fixed-attempts",)"
               R"("flush_grace_ms":750,"ca_cpu":7}})";
        const auto lookup = parse({"turtle", "run", "--profile", lookup_path}).run;
        require(lookup.lookup.enabled &&
                    lookup.lookup.cache_mode == turtle::model::CacheMode::FixedSnapshot &&
                    lookup.lookup.object_file == (dir / "objects/chain.pem").string() &&
                    lookup.lookup.snapshot_file == (dir / "cache/warm.json").string(),
                "lookup profile values or relative paths were not applied");
        require(lookup.samples == 4 &&
                    lookup.failure_policy == turtle::model::FailurePolicy::FixedAttempts &&
                    lookup.flush_grace_ms == 750 && lookup.ca_cpu == 7,
                "attempt policy settings were not applied");

        const auto fallback = parse({"turtle", "run", "--pki", (dir / "other-pki").string()}).run;
        require(!fallback.lookup.enabled &&
                    fallback.lookup.cache_mode == turtle::model::CacheMode::Empty &&
                    fallback.lookup.snapshot_file.empty() &&
                    fallback.lookup.object_file == (dir / "other-pki/server-chain.pem").string(),
                "lookup defaults did not use the final TLS certificate path");
        require(fallback.failure_policy == turtle::model::FailurePolicy::FailFast &&
                    fallback.flush_grace_ms == 500 && fallback.ca_cpu == -1,
                "attempt policy defaults changed");

        const auto output = dir / "network-output";
        const auto manifest_path = (dir / "network-manifest.json").string();
        std::ofstream(manifest_path)
            << "{\"type\":\"turtle-network-manifest\",\"schema\":1,"
               "\"namespace_fds\":{\"client\":10,\"server\":11,\"ca\":12},"
               "\"addresses\":{\"client_tls\":\"10.203.1.2\","
               "\"server\":\"10.203.2.2\",\"client_ca\":\"10.203.3.2\","
               "\"ca\":\"10.203.4.2\"},"
               "\"interfaces\":{\"client_tls\":\"ctls\",\"server\":\"stls\","
               "\"client_ca\":\"cca\",\"ca\":\"ca0\","
               "\"router_client_tls\":\"rctls\",\"router_server\":\"rstls\","
               "\"router_client_ca\":\"rcca\",\"router_ca\":\"rca0\"},"
               "\"net_profile\":{\"type\":\"turtle-netem-profile\",\"schema\":1},"
               "\"provenance_file\":\""
            << (output / "network-provenance.json").string() << "\",\"observations_file\":\""
            << (output / "network-observations.jsonl").string() << "\",\"phase_control_fd\":13}";
        const auto network = parse({"turtle", "run", "--network-manifest", manifest_path,
                                    "--output", output.string()})
                                 .run;
        require(network.network_manifest == manifest_path && network.network_handoff.has_value(),
                "network manifest was not loaded");
        require(network.network_handoff->client_namespace_fd == 10 &&
                    network.network_handoff->server_namespace_fd == 11 &&
                    network.network_handoff->ca_namespace_fd == 12 &&
                    network.network_handoff->phase_control_fd == 13 &&
                    network.network_handoff->client_tls_address == "10.203.1.2" &&
                    network.network_handoff->router_ca_interface == "rca0",
                "network manifest handoff values changed");

        const auto pure_manifest_path = (dir / "pure-network-manifest.json").string();
        std::ofstream(pure_manifest_path)
            << "{\"type\":\"turtle-network-manifest\",\"schema\":1,"
               "\"namespace_fds\":{\"client\":20,\"server\":21},"
               "\"addresses\":{\"client_tls\":\"10.203.1.2\","
               "\"server\":\"10.203.2.2\"},"
               "\"interfaces\":{\"client_tls\":\"ctls\",\"server\":\"stls\","
               "\"router_client_tls\":\"rctls\",\"router_server\":\"rstls\"},"
               "\"net_profile\":{\"type\":\"turtle-netem-profile\",\"schema\":1},"
               "\"provenance_file\":\""
            << (output / "pure-network-provenance.json").string() << "\",\"observations_file\":\""
            << (output / "pure-network-observations.jsonl").string()
            << "\",\"phase_control_fd\":22}";
        const auto pure_network = parse({"turtle", "run", "--network-manifest", pure_manifest_path,
                                         "--output", output.string()})
                                      .run;
        require(pure_network.network_handoff.has_value() &&
                    pure_network.network_handoff->client_namespace_fd == 20 &&
                    pure_network.network_handoff->server_namespace_fd == 21 &&
                    pure_network.network_handoff->ca_namespace_fd == -1 &&
                    pure_network.network_handoff->phase_control_fd == 22 &&
                    pure_network.network_handoff->client_ca_address.empty() &&
                    pure_network.network_handoff->ca_address.empty() &&
                    pure_network.network_handoff->client_ca_interface.empty() &&
                    pure_network.network_handoff->ca_interface.empty() &&
                    pure_network.network_handoff->router_client_ca_interface.empty() &&
                    pure_network.network_handoff->router_ca_interface.empty(),
                "lookup-disabled network manifest did not preserve absent CA members");
        std::ofstream(lookup_path)
            << R"({"lookup":{"enabled":true,"object_file":"objects/chain.pem"}})";
        require(rejects({"turtle", "run", "--profile", lookup_path, "--network-manifest",
                         pure_manifest_path, "--output", output.string()}),
                "lookup-enabled run accepted a network manifest without CA members");
        require(turtle::config::usage().find("--network-manifest FILE") != std::string::npos,
                "network manifest option is missing from help");

        std::ofstream(lookup_path)
            << R"({"lookup":{"enabled":true,"cache_mode":"fixed-snapshot"}})";
        require(rejects({"turtle", "run", "--profile", lookup_path}),
                "fixed-snapshot without snapshot_file was accepted");
        std::ofstream(lookup_path)
            << R"({"lookup":{"cache_mode":"empty","snapshot_file":"warm.json"}})";
        require(rejects({"turtle", "run", "--profile", lookup_path}),
                "empty cache with snapshot_file was accepted");
        std::ofstream(lookup_path) << R"({"lookup":{"cache_mode":"other"}})";
        require(rejects({"turtle", "run", "--profile", lookup_path}),
                "unknown cache mode was accepted");
        std::ofstream(lookup_path) << R"({"lookup":{"enabled":true,"extra":1}})";
        require(rejects({"turtle", "run", "--profile", lookup_path}),
                "unknown lookup field was accepted");
        std::ofstream(lookup_path) << R"({"measurement":{"failure_policy":"retry"}})";
        require(rejects({"turtle", "run", "--profile", lookup_path}),
                "unknown failure policy was accepted");
        for (const char* grace : {"0", "5001"}) {
            std::ofstream(lookup_path) << "{\"measurement\":{\"flush_grace_ms\":" << grace << "}}";
            require(rejects({"turtle", "run", "--profile", lookup_path}),
                    "out-of-range flush grace was accepted");
        }
        std::ofstream(lookup_path) << R"({"measurement":{"ca_cpu":-2}})";
        require(rejects({"turtle", "run", "--profile", lookup_path}),
                "invalid CA CPU was accepted");
        require(rejects({"turtle", "run", "--attempts", "3"}),
                "separate attempts CLI was accepted");
        require(rejects({"turtle", "run", "--lookup", "true"}), "lookup CLI synonym was accepted");
        require(rejects({"turtle", "run", "--network-manifest", manifest_path, "--network-manifest",
                         manifest_path, "--output", output.string()}),
                "duplicate network manifest was accepted");
        const auto invalid_manifest = (dir / "invalid-network-manifest.json").string();
        std::ofstream(invalid_manifest) << R"({"type":"wrong","schema":1})";
        require(rejects({"turtle", "run", "--network-manifest", invalid_manifest, "--output",
                         output.string()}),
                "invalid network manifest type was accepted");

        for (const auto* cipher : {"TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256",
                                   "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384"}) {
            require(rejects({"turtle", "run", "--cipher", cipher}),
                    "out-of-scope cipher suite accepted");
            std::ofstream(path) << "{\"tls\":{\"cipher\":\"" << cipher << "\"}}";
            require(rejects({"turtle", "run", "--profile", path}),
                    "out-of-scope profile cipher accepted");
            require(
                parse({"turtle", "run", "--profile", path, "--cipher", "TLS_AES_128_GCM_SHA256"})
                        .run.tls.cipher == "TLS_AES_128_GCM_SHA256",
                "explicit fixed cipher override was rejected");
        }
        std::filesystem::remove_all(dir);
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        std::filesystem::remove_all(dir);
        return 1;
    }
}
