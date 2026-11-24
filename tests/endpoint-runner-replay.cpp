#include "native/evidence.hpp"
#include <algorithm>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>

using Json = nlohmann::json;
void check(bool ok, const char *why) {
  if (!ok) throw std::runtime_error(why);
}
int main(int argc, char **argv) try {
  check(argc == 3, "usage: endpoint-offer-replay NDJSON INPUT");
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
  auto report = turtle::native::analyze_evidence(contents.str(), context);
  check(report.at("status") == "verified" &&
            report.at("timeline").at("CAD").at("write_offer_pairs") == true,
        "partial writes did not qualify");
  if (plain.size() != 4) return 0;
  Json events = Json::array();
  std::istringstream lines(contents.str());
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
