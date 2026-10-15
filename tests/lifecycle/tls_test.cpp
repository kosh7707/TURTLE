#include "lifecycle/lifecycle.hpp"
#include "model/run_config.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>
#include <unistd.h>
int main(int argc, char** argv) {
    if (argc < 3 || argc > 5)
        return 2;
    const auto root = std::filesystem::temp_directory_path() /
                      ("turtle-real-runtime-" + std::to_string(::getpid()));
    try {
        turtle::model::RunConfig config;
        config.adapter_directory = argv[1];
        config.client_adapter = argc > 3 ? argv[3] : "openssl";
        config.server_adapter = argc > 4 ? argv[4] : config.client_adapter;
        config.samples = 2;
        config.warmups = 1;
        config.perf = false;
        config.calibration_samples = 2;
        auto pki = std::filesystem::absolute(argv[2]);
        config.tls.ca_file = (pki / "ca.pem").string();
        config.tls.server_certificate = (pki / "server-chain.pem").string();
        config.tls.server_key = (pki / "server.key").string();
        config.tls.client_certificate = (pki / "client-chain.pem").string();
        config.tls.client_key = (pki / "client.key").string();
        for (bool mutual : {false, true})
            for (auto mode : {turtle::model::Mode::Timing, turtle::model::Mode::Memory}) {
                config.tls.mutual_auth = mutual;
                config.mode = mode;
                config.output_directory = (root / (std::string(mutual ? "mutual-" : "server-") +
                                                   turtle::model::name(mode)))
                                              .string();
                if (turtle::lifecycle::run(config))
                    throw std::runtime_error("TLS runtime failed");
                for (const char* sample : {"sample-000001", "sample-000002"})
                    for (const char* role : {"client", "server"}) {
                        std::ifstream in(std::filesystem::path(config.output_directory) / sample /
                                         (std::string(role) + ".jsonl"));
                        std::string line;
                        std::getline(in, line);
                        auto data = nlohmann::json::parse(line);
                        if (!data.at("valid").get<bool>() ||
                            data.at("declaration").at("is_mock").get<bool>())
                            throw std::runtime_error("not a valid real TLS sample");
                        std::vector<std::size_t> sent(config.warmups + 1),
                            received(config.warmups + 1);
                        while (std::getline(in, line)) {
                            const auto event = nlohmann::json::parse(line);
                            const auto index = event.at("connection").get<std::size_t>();
                            if (event.at("call") == "negotiated" &&
                                event.at("sequence").get<std::uint64_t>() <=
                                    data.at("connections")
                                        .at(index)
                                        .at("end_sequence")
                                        .get<std::uint64_t>())
                                throw std::runtime_error(
                                    "negotiated metadata inside measured boundary");
                            if (event.at("kind") == "CALL_END" &&
                                (event.at("call") == "app_send" ||
                                 event.at("call") == "app_recv")) {
                                const auto bytes = event.at("transferred").get<std::size_t>();
                                if (event.at("requested").get<std::size_t>() == 0 ||
                                    bytes > event.at("requested").get<std::size_t>())
                                    throw std::runtime_error("application byte fields incorrect");
                                if (event.at("result") == static_cast<int>(turtle::Step::Done) &&
                                    bytes == 0)
                                    throw std::runtime_error(
                                        "successful application result missing bytes");
                                (event.at("call") == "app_send" ? sent : received).at(index) +=
                                    bytes;
                            }
                        }
                        for (std::size_t i = 0; i < sent.size(); ++i)
                            if (sent[i] != config.tls.application_bytes ||
                                received[i] != config.tls.application_bytes)
                                throw std::runtime_error("application byte totals differ");
                        for (const auto& c : data.at("connections"))
                            if (c.at("negotiated").at("version") != "TLS1.3" ||
                                !c.at("application_verified").get<bool>())
                                throw std::runtime_error("TLS or application result missing");
                    }
            }
        std::cout << "real TLS runtime passed: " << root << '\n';
    } catch (const std::exception& e) {
        std::cerr << e.what() << " (artifacts: " << root << ")\n";
        return 1;
    }
}
