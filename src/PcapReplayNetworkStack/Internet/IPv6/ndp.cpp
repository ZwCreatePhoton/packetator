#include "PcapReplayNetworkStack/pcap_replay_network_stack.h"

void PcapReplayNetworkStack::perform_early_unsolicited_na()
{
    bool is_ipv4 = netdev.ip_address.find('.') != std::string::npos;
    if (!is_ipv4)
    {
        std::string sip = netdev.ip_address;
        send_ndp_neighbor_advertisement("FF02::1" , netdev.ip_address, "33:33:00:00:00:01", netdev.mac_address, false, true);
        usleep(early_arp_wait_time);
    }
}