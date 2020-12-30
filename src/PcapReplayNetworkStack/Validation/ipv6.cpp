#include "PcapReplayNetworkStack/pcap_replay_network_stack.h"

bool PcapReplayNetworkStack::received_expected_ipv6()
{
    bool result = true;
    if (config.tx_event_packet_count || (config.tx_event_transport && config.tx_event_packet_count_if_no_transport && complete_original_connection_table.size() == 0))
    {
        result &= original_ipv6defragmenter_rx->packet_count() == ipv6defragmenter_rx->packet_count();
        result &= original_ipv6defragmenter_tx->packet_count() == ipv6defragmenter_tx->packet_count();
    }
    if (config.tx_event_datagram_count || (config.tx_event_transport && config.tx_event_datagram_count_if_no_transport && complete_original_connection_table.size() == 0))
    {
        result &= original_ipv6defragmenter_rx->datagram_count() == ipv6defragmenter_rx->datagram_count();
        result &= original_ipv6defragmenter_tx->datagram_count() == ipv6defragmenter_tx->datagram_count();
    }
    return result;
}
