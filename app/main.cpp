#include <iostream>
#include <boost/program_options.hpp>
#include "ip_filter.h"

namespace po = boost::program_options;

static constexpr int kOk{};
static constexpr int kErrorIpFilter{1};
static constexpr int kErrorParseOptions{2};
static char const *const kHelp{"help,h"};
static char const *const kAllowedOptions{
    "IPv4 filter allowed options:\n"
    "-h, --help            produce help message\n"
    "-i, --input-file      input file\n"
    "-o, --output-file     output file\n"
    "-s, --use-standard    use the c++ standard: 17 or 23\n\0"
};
static char const *const kInputFile{"input-file"};
static char const *const kOutputFile{"output-file"};
static char const *const kStandard{"use-standard"};

struct options_t {
    std::string const in{};
    std::string const out{};
    int const standard{};
};

std::optional<options_t> ParseOptions(int argc, char **argv) {
    // Объявление опций
    po::options_description desc{kAllowedOptions};
    desc.add_options()
            ("help,h", "produce help message")
            ("input-file,i", po::value<std::string>(), "input file")
            ("output-file,o", po::value<std::string>(), "use the c++ standard: 17 or 23")
            ("use-standard,s", po::value<int>()->default_value(17), "output file");

    // Парсинг аргументов командной строки
    po::variables_map vm{};
    po::store(po::parse_command_line(argc, argv, desc), vm);
    po::notify(vm);

    // Обработка опций
    if (vm.contains(kHelp)) {
        std::cout << desc << ".\n";
        return {};
    }

    std::string in{};
    if (vm.contains(kInputFile)) {
        in = vm[kInputFile].as<std::string>();
        std::cout << "Options \"input-file\" was set to " << in << ".\n";
    }

    int standard{};
    if (vm.contains(kStandard)) {
        standard = vm[kStandard].as<int>();
    } else {
        std::cout << "The c++ standard is not used. the default value is c++17.\n";
    }

    std::string out{};
    if (vm.contains(kOutputFile)) {
        out = vm[kOutputFile].as<std::string>();
        std::cout << "Output file was set to " << out << ".\n";
    }
    return options_t{in, out, standard};
}

int main(int argc, char **argv) {
    if (auto const opt_options{ParseOptions(argc, argv)}; !opt_options.has_value()) {
        return kErrorParseOptions;
    } else {
        auto const [in, out, standard]{opt_options.value()};
        IpFilter ip_filter{in, out, standard};
        if (!ip_filter.Parsing()) {
            return kErrorIpFilter;
        }
        return kOk;
    }
}
