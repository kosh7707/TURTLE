#include "report/report.hpp"
#include <iostream>
#include <string_view>
int main(int argc, char** argv) {
    try {
        const bool repeated_context = argc == 4 && std::string_view(argv[3]) == "--repeated-context";
        if (argc != 3 && !repeated_context) {
            std::cerr << "usage: turtle-report INPUT_FILE_OR_DIRECTORY OUTPUT_DIRECTORY "
                         "[--repeated-context]\n";
            return 2;
        }
        const auto r = turtle::report::summarize(argv[1], argv[2], repeated_context);
        std::cout << r.at("groups").size() << " groups, " << r.at("invalid_samples")
                  << " invalid samples\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << e.what() << '\n';
        return 1;
    }
}
