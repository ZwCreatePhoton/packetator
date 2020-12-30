#include "PcapReplayNetworkStack/pcap_replay_network_stack.h"

bool PcapReplayNetworkStack::received_expected_ip()
{
    bool result = true;
    result &= received_expected_ipv4();
    result &= received_expected_ipv6();
    if (config.tx_event_transport)
        result &= received_expected_transport();
    return result;
}
