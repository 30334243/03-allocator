#include <gtest/gtest.h>
#include <ranges>
#include <filesystem>
#include <cstdio>
#include <algorithm>
#include <boost/process.hpp>
#include <boost/uuid/detail/md5.hpp>
#include <boost/algorithm/hex.hpp>
#include "ip_filter.h"

std::string md5sum(std::string const &input) {
    boost::uuids::detail::md5 md5;
    boost::uuids::detail::md5::digest_type digest;

    md5.process_bytes(input.data(), input.size());
    md5.get_digest(digest);

    const auto charDigest = reinterpret_cast<const char *>(&digest);
    std::string result;
    boost::algorithm::hex(charDigest, charDigest + sizeof(digest), std::back_inserter(result));

    return result;
}

//--------------------TESTS--------------------

TEST(test_ip_filter, ip_parsing) {
    static constexpr int kEthalonSizeIPs{2};

    static std::string const kEthalonIP{
        "255.255.255.255"
    };
    static std::vector<std::string> const in{
        "255.255.255.255\t",
        "255.255.255.255.255\t",
        "2555.255.255.255\t",
        "255.2555.255.255\t",
        "255.255.2555.255\t",
        "255.255.255.2555\t",
        "255.255.255\t",
        "255.255.255.255",
        "xxx.255.255.255\t",
        "abc.255.255.255\t",
    };
    IpFilter ip_filter{};
    ASSERT_NO_THROW(ip_filter.ParsingInputVector(in));

    auto const ips{ip_filter.GetIPs()};
    ASSERT_EQ(ips.size(), kEthalonSizeIPs);
    for (auto const &ip: ips) {
        ASSERT_TRUE(std::ranges::equal(ip.to_string(), kEthalonIP));
    }
}

TEST(test_ip_filter, ip_sorting) {
    static std::vector<std::string> const kEthalonIP{
        "255.255.255.255",
        "128.128.128.128",
        "1.1.1.1"
    };
    static std::vector<std::string> const in{
        "128.128.128.128\t",
        "255.255.255.255\t",
        "1.1.1.1\t"
    };
    IpFilter ip_filter{};
    ASSERT_NO_THROW(ip_filter.ParsingInputVector(in));
    ip_filter.Sorting(std::greater{});
    auto const ips{ip_filter.GetIPs()};
    ASSERT_EQ(ips.size(), kEthalonIP.size());

    int const size{static_cast<int>(ips.size())};
    std::ranges::for_each(std::views::iota(0, size), [&ips](int const i) {
        ASSERT_TRUE(std::ranges::equal(ips[i].to_string(), kEthalonIP[i]));
    });
}

TEST(test_ip_filter, ip_filter_cxx23) {
    static std::string const kFileTest{"ip_filter.tsv"};
    static constexpr int kCxx23{23};

    IpFilter ip_filter{kFileTest, "", kCxx23};

    std::stringstream buffer{};
    std::streambuf *old_cout{std::cout.rdbuf()};
    std::cout.rdbuf(buffer.rdbuf());

    ASSERT_TRUE(ip_filter.Parsing());

    std::cout.rdbuf(old_cout);
    std::string const output{buffer.str()};

#ifdef WSL_SPECIFIC_FLAG
    ASSERT_EQ(md5sum(buffer.str()), "B2A7E724E8AE0D27CAD3649C1ADAB35F");
#elifdef WINDOWS_SPECIFIC_FLAG
    ASSERT_EQ(md5sum(buffer.str()), "24E7A7B2270DAEE89C64D3CA5FB3DA1A");
#else
    ASSERT_TRUE(false);
#endif
}

TEST(test_ip_filter, ip_filter_cxx17) {
    static std::string const kFileTest{"ip_filter.tsv"};
    static constexpr int kCxx17{17};

    IpFilter ip_filter{kFileTest, "", kCxx17};

    std::stringstream buffer{};
    std::streambuf *old_cout{std::cout.rdbuf()};
    std::cout.rdbuf(buffer.rdbuf());

    ASSERT_TRUE(ip_filter.Parsing());

    std::cout.rdbuf(old_cout);
    std::string const output{buffer.str()};

#ifdef WSL_SPECIFIC_FLAG
    ASSERT_EQ(md5sum(buffer.str()), "B2A7E724E8AE0D27CAD3649C1ADAB35F");
#elifdef WINDOWS_SPECIFIC_FLAG
    ASSERT_EQ(md5sum(buffer.str()), "24E7A7B2270DAEE89C64D3CA5FB3DA1A");
#else
    ASSERT_TRUE(false);
#endif
}
