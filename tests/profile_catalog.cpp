#include "profiling/profiling.hpp"
#include <filesystem>
#include <iostream>
#include <sys/stat.h>
using namespace turtle::artifact;
namespace fs = std::filesystem;
int main(int argc, char **argv) try {
  if (argc != 3)
    return 1;
  fs::create_directories(argv[1]);
  auto pattern = (fs::absolute(argv[1]) / "catalog-XXXXXX").string();
  if (!::mkdtemp(pattern.data()))
    return 1;
  const fs::path root(pattern);
  write_text(root / "perf.data", "catalog parser fixture");
  const auto executable = fs::absolute(argv[2]);
  for (const auto &[module, expected] :
       {std::pair{"/tmp/perf-vdso.so-aB123z", true},
        std::pair{"[vdso32]", true},
        std::pair{"/tmp/perf-vdso.so-aB123z/mapped.so", false},
        std::pair{"/usr/lib/unspecified.so", false}}) {
    write_text(root / "catalog", std::string("0123 [vdso]\n") +
                                     std::string(41, ' ') + module + "\n");
    save(root / "profile.json",
         {{"perf", executable.string()}, {"commands", Json::array()}});
    turtle::profiling::finish(root, 0);
    auto p = load(root / "profile.json");
    if ((p.at("status") == "collected") != expected ||
        p.at("unparsed_build_ids").empty() != expected)
      return 1;
  }
  fs::remove_all(root);
  std::cout
      << "Padded virtual vs unresolved file-backed modules distinguished\n";
  return 0;
} catch (const std::exception &e) {
  std::cerr << e.what() << '\n';
  return 1;
}
