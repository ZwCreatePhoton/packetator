#include <tins/tins.h>
#include "gtest/gtest.h"

#include <TCPIPNetworkStack/Link/networking.h>

void setup(const std::string& iface)
{
    srand(time(NULL)); // seed the PRNG

    auto *interface0 = new Tins::NetworkInterface(iface);
    auto *sender0 = new Tins::PacketSender(*interface0);
    sender0->open_l2_socket(sender0->default_interface());
    networking.AddTransmitter(sender0);
}

int main(int argc, char** argv)
{
    std::string iface_ext = "eth2";
    std::string iface_int = "eth3";
    std::string target_ip = "10.3.1.1";
    std::string target_ip6_ext = "fdda:dead:beef:dab3::1:1";
    std::string target_ip6_int = "fdda:dead:beef:dab1::1:1";

    std::string w7_ip6 = "fdda:dead:beef:dab1:2222:7ecc:f5c3:6cbb";

    setup(iface_ext);
    setup(iface_int);

    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();


//    test_arp_table(iface, target_ip);
//    test_icmp_echo_request(iface, target_ip);

//    test_neighbor_solicitation(iface_int, target_ip6_int);
//    test_handle_neighbor_advertisment(iface_int, w7_ip6);
//    test_send_icmpv6_echo_request(iface_int, w7_ip6);
//    test_handle_icmpv6_echo_request(iface_int, w7_ip6);
}
