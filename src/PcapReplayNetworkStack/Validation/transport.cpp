#include <cstring>

#include "PcapReplayNetworkStack/pcap_replay_network_stack.h"


bool PcapReplayNetworkStack::received_expected_transport()
{
    bool result = true;
    // TODO: Support dependence between UDP & TCP.
    // e.g. DNS over UDP query before an HTTP over TCP request. Replaying the TCP connection in parallel or before the UDP connection would be incorrect.
    result &= received_expected_udp();
    result &= received_expected_tcp();
    return result;
}

bool PcapReplayNetworkStack::received_expected_transport_data(Connection *original_connection, bool server)
{
    // Conditions that need to be meet to proceed with TX:
    //      1. original stream data is a "substring" of replayed stream data (replayed connection is further along than original connection)

    if (original_connection == nullptr)
        return true;

    bool result = true;

    Connection *replayed_connection = convert_Connection(original_connection, true);
    if (replayed_connection == nullptr)
    {
        result &= server ? original_connection->server_payload().empty() : original_connection->client_payload().empty();
        return result;
    }

    auto &original_payload = server ? original_connection->server_payload() : original_connection->client_payload();
    auto &replayed_payload = server ? replayed_connection->server_payload() : replayed_connection->client_payload();

    // result = (replayed_payload[:len(original_payload)] == original_payload)
    result &= replayed_payload.size() >= original_payload.size();
    if (result)
        result &= (std::memcmp(replayed_payload.data(), original_payload.data(), original_payload.size()) == 0);

    return result;
}

bool PcapReplayNetworkStack::received_expected_transport_data(Connection *original_connection)
{
    return received_expected_transport_data(original_connection, true) && received_expected_transport_data(original_connection, false);
}
