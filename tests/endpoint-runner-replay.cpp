#include "native/evidence.hpp"
#include <algorithm>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>

using Json = turtle::artifact::Json;
void check(bool ok, const char *why) {
  if (!ok) throw std::runtime_error(why);
}
int main(int argc, char **argv) try {
  check(argc == 3 || (argc == 4 && std::string(argv[3]) == "--after-end"),
        "usage: endpoint-offer-replay NDJSON INPUT [--after-end]");
  std::ifstream f(argv[1]);
  std::ostringstream contents;
  contents << f.rdbuf();
  std::string plain(argv[2]), hex;
  for (const unsigned char byte : plain) {
    constexpr char digits[] = "0123456789abcdef";
    hex += digits[byte >> 4];
    hex += digits[byte & 15];
  }
  Json context = {{"role", "client"}, {"scenario", "S1"}, {"auth", "server"},
                  {"run_id", "run"}, {"connection_id", "conn"},
                  {"scenario_contract", turtle::native::endpoint_contract_id},
                  {"messages", {{"CAD", plain.size()}}},
                  {"plaintext", {{"CAD", hex}}}};
  const auto raw = contents.str();
  auto report = turtle::native::analyze_evidence(raw, context);
  check(report.at("observer_stream") == "complete", "missing complete stream");
  if (argc == 4) {
    check(report.at("status") == "contradicted" &&
              report.at("facts").at("endpoint_unsupported") == true,
          "complete stream lost the fact after END");
    const auto end = raw.find('\n', raw.find("\"name\":\"end\""));
    check(end != raw.npos, "missing END frame");
    const auto prefix = turtle::native::analyze_evidence(raw.substr(0, end + 1),
                                                         context);
    check(prefix.at("status") == "invalid" &&
              prefix.at("errors").at(0) == "observer_recording_incomplete" &&
              prefix.at("events").back().at("name") == "end",
          "line-boundary truncation after END qualified");
    return 0;
  }
  check(report.at("status") == "verified" &&
            report.at("timeline").at("CAD").at("write_offer_pairs") == true,
        "partial writes did not qualify");
  const auto seal_start = raw.rfind("\n", raw.size() - 2) + 1;
  const auto prefix = raw.substr(0, seal_start);
  auto incomplete = turtle::native::analyze_evidence(
      prefix + "{\"kind\":\"observer_loss\"}\n", context);
  check(incomplete.at("status") == "invalid" &&
            incomplete.at("errors").at(0) == "observer_recording_incomplete",
        "an otherwise valid observation prefix qualified after recorded loss");
  if (plain.size() != 4) return 0;
  Json events = Json::array();
  std::istringstream lines(raw);
  for (std::string line; std::getline(lines, line);)
    events.push_back(Json::parse(line));
  auto suffix = std::find_if(events.begin(), events.end(),
                             [](auto &e) { return e.contains("offer_ref"); });
  check(suffix != events.end(), "no compact offer");
  const auto original = *suffix;
  auto replay = [&] {
    std::string bytes;
    for (const auto &ev : events) bytes += ev.dump() + "\n";
    return turtle::native::analyze_evidence(bytes, context);
  };
  check(turtle::native::analyze_evidence(prefix, context).at("status") ==
            "invalid",
        "missing observer seal qualified");
  check(turtle::native::analyze_evidence(raw + raw.substr(seal_start), context)
            .at("status") == "invalid" &&
            turtle::native::analyze_evidence(raw + prefix, context)
                .at("status") == "invalid",
        "trailing observer rows qualified");
  const auto seal = events.back();
  const Json wrong = {{"kind", "other"}, {"v", 1}, {"count", -1},
                      {"pid", nullptr}, {"role", "server"},
                      {"run_id", "other"}, {"connection_id", "other"}};
  for (const auto &[key, value] : wrong.items()) {
    events.back()[key] = value;
    check(replay().at("status") == "invalid", "malformed seal qualified");
    events.back() = seal;
  }
  events.back()["count"] = 1;
  check(replay().at("status") == "invalid", "wrong seal count qualified");
  events.back() = seal;
  events.back()["pid"] = seal.at("pid").get<uint64_t>() + 1;
  check(replay().at("status") == "invalid", "wrong seal pid qualified");
  events.back() = seal;
  events.front()["v"] = 1;
  check(replay().at("status") == "invalid", "mixed protocol qualified");
  events.front()["v"] = turtle::native::buffered_evidence_version;
  for (auto key : {"offer_ref", "suffix_offset", "length", "tid", "ns"}) {
    (*suffix)[key] = 1;
    check(replay().at("status") == "invalid", "tampered offer qualified");
    *suffix = original;
  }
  (*suffix)["hex"] = "6e67";
  check(replay().at("status") == "invalid", "ambiguous explicit/reference offer");
  *suffix = original;
  auto &accepted = *(suffix + 1);
  accepted["hex"] = "0000";
  check(replay().at("status") == "contradicted", "wrong returned prefix accepted");
  accepted["hex"] = "6e67";
  context.erase("scenario_contract");
  check(replay().at("status") == "invalid", "legacy archive accepted compact offers");
  return 0;
} catch (const std::exception &e) {
  std::cerr << e.what() << '\n';
  return 1;
}
