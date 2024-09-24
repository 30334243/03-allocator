#include <numeric>
#include <string>
#include <utility>
#include <vector>
#include <tuple>
#include <sstream>
#include "ip_filter.h"

void IpFilter::parsing_cxx17(std::string const &line) {
    static constexpr int kMaxSizeIpString{16};
    static constexpr int kNumIpElements{4};

    if (auto const beg_tab{std::find(line.cbegin(), line.cend(), '\t')}; beg_tab != line.cend()) {
        size_t const len_ip_str{static_cast<size_t>(std::distance(line.cbegin(), beg_tab))};
        if (kMaxSizeIpString < len_ip_str) {
        } else if (auto const ip_elements{splitString(line.substr(0, len_ip_str), '.')};
            kNumIpElements != ip_elements.size()) {
        } else {
            ips_cxx17.emplace_back(parsingIpElements(ip_elements));
        }
    }
}

std::tuple<std::string, uint32_t> IpFilter::parsingIpElements(std::vector<std::string> const &ip_elements) {
    static constexpr int kStep{8};
    static constexpr int kMaxNumPoint{3};

    std::string ip_str{};
    uint32_t ip_addr{};
    for (size_t i{}, shift{24}; i < ip_elements.size(); ++i, shift -= kStep) {
        auto const &elm{ip_elements[i]};
        if (i < kMaxNumPoint) {
            ip_str.append(elm + '.');
        } else {
            ip_str.append(elm);
        }
        ip_addr |= std::stol(elm) << shift;
    }
    return std::make_tuple(ip_str, ip_addr);
}

void IpFilter::print(std::string const &str) {
    if (dst.is_open()) {
        dst << str << '\n';
    } else {
        std::cout << str << '\n';
    }
}

IpFilter::IpFilter(std::string file, std::string const &out, int const standard) : file{std::move(file)}, dst{out},
    standard{standard} {
}

uint64_t IpFilter::Version() {
    return PROJECT_VERSION_PATCH;
}

bool IpFilter::isAllDigits(std::string const &str) {
    for (char ch: str) {
        if (!std::isdigit(ch)) {
            return false;
        }
    }
    return true;
}

std::vector<std::string> IpFilter::splitString(std::string const &str, char const delimiter) {
    std::vector<std::string> tokens;
    std::istringstream iss(str);
    std::string token;

    while (std::getline(iss, token, delimiter)) {
        if (isAllDigits(token)) {
            tokens.push_back(token);
        }
    }

    return tokens;
}

bool IpFilter::Parsing() {
    switch (standard) {
        case kCxx17:
            if (!parsingCxx17()) {
                return false;
            }
            break;
        case kCxx23:
            if (!parsingCxx23()) {
                return false;
            }
            break;
        default:
            std::cout << "Unknows standart=" << standard << '\n';
            return false;
    }
    return true;
}

bool IpFilter::parsingCxx23() {
    bool ret{};
    if (std::ifstream src{file}; !src.fail()) {
        std::string line{};
        while (std::getline(src, line)) {
            parsing_cxx23(line);
        }
        Sorting(std::greater{});
        filter(Otus::task_1, Otus::task_2, Otus::task_3, Otus::task_4);
        ret = true;
    } else {
        std::string line{};
        while (std::getline(std::cin, line)) {
            parsing_cxx23(line);
        }
        Sorting(std::greater{});
        filter(Otus::task_1, Otus::task_2, Otus::task_3, Otus::task_4);
        ret = true;
    }
    return ret;
}

void IpFilter::parsing_cxx23(std::string const &line) {
    for (auto const &ip: std::views::split(line, '\t') |
                         std::views::take(1) |
                         std::views::filter(is_valid_size) |
                         std::views::filter(is_valid_num_points) | // for windows
                         std::views::transform(convert_to_ip) |
                         std::views::filter(is_valid_ip) |
                         std::views::transform(get_ip)) {
        ips_cxx23.emplace_back(ip);
    }
}

void IpFilter::ParsingInputVector(std::vector<std::string> const &in) {
    for (auto const &line: in) {
        parsing_cxx23(line);
    }
}

void IpFilter::Sorting(
    std::function<bool(boost::asio::ip::address_v4 const &, boost::asio::ip::address_v4 const &)> func) {
    std::ranges::sort(ips_cxx23, func);
}

void IpFilter::filter_task_1() {
    for (auto const &[str,_]: ips_cxx17) {
        print(str);
    }
}

void IpFilter::filter_task_2() {
    static constexpr int kFirstByte{3};

    for (auto const &[str,addr]: ips_cxx17) {
        uint8_t const *raw{reinterpret_cast<uint8_t const *>(&addr)};
        if (raw[kFirstByte] == 1) {
            print(str);
        }
    }
}

void IpFilter::filter_task_3() {
    static constexpr int kFirstByte{3};
    static constexpr int kSecondByte{2};

    for (auto const &[str,addr]: ips_cxx17) {
        uint8_t const *raw{reinterpret_cast<uint8_t const *>(&addr)};
        if (raw[kFirstByte] == 46 && raw[kSecondByte] == 70) {
            print(str);
        }
    }
}

void IpFilter::filter_task_4() {
    for (auto const &[str,addr]: ips_cxx17) {
        uint8_t const *raw{reinterpret_cast<uint8_t const *>(&addr)};
        if (std::find(raw, raw + 4, 46) != (raw + 4)) {
            print(str);
        }
    }
}

bool IpFilter::parsingCxx17() {
    bool ret{};
    if (std::ifstream src{file}; !src.fail()) {
        std::string line{};
        while (std::getline(src, line)) {
            parsing_cxx17(line);
        }
        std::sort(ips_cxx17.begin(), ips_cxx17.end(), [](auto &lhs, auto &rhs) {
            auto [_1,addr1]{lhs};
            auto [_2,addr2]{rhs};
            return addr2 < addr1;
        });
        filter_task_1();
        filter_task_2();
        filter_task_3();
        filter_task_4();
        ret = true;
    } else {
        std::string line{};
        while (std::getline(std::cin, line)) {
            parsing_cxx17(line);
        }
        std::sort(ips_cxx17.begin(), ips_cxx17.end(), [](auto &lhs, auto &rhs) {
            auto [_1,addr1]{lhs};
            auto [_2,addr2]{rhs};
            return addr2 < addr1;
        });
        filter_task_1();
        filter_task_2();
        filter_task_3();
        filter_task_4();
        ret = true;
    }
    return ret;
}

std::vector<boost::asio::ip::address_v4> IpFilter::GetIPs() const {
    return ips_cxx23;
}
