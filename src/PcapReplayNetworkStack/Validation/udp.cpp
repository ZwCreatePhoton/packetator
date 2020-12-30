#include <utils.h>
#include "PcapReplayNetworkStack/pcap_replay_network_stack.h"

bool PcapReplayNetworkStack::received_expected_udp()
{
    // TODO: merge received_expected_udp and received_expected_tcp into received_expected_transport ?

    if (config.tx_event_udp_all_connections)
    {
        std::vector<Connection *> *original_connections = original_connection_table.all();
        for (auto original_connection : *original_connections)
        {
            if (original_connection->protocol() == IPPROTO_UDP)
            {
                if (!received_expected_udp_connection((UdpConnection *)original_connection))
                    return false;
            }
        }
        delete original_connections;
        return true;
    }
    else
    {
        if (packets_index + 1 >= packets.size())
            return true;
        // Find the UdpConnection object relevant for packets[packet_index + 1] (the next TX packet)
        auto packet = packets[packets_index + 1];
        std::unique_ptr<Tuple::FiveTuple> original_fivetuple = Tuple::packet_to_FiveTuple(packet);
        Tuple::ClientServerFiveTuple original_cs5t = FiveTuple_to_ClientServerFiveTuple(*original_fivetuple, true);
        std::unique_ptr<Tuple::ClientServerFourTuple> original_cs4t = Tuple::ClientServerFiveTuple_to_ClientServerFourTuple(original_cs5t);
        auto *original_connection = original_connection_table.lookup(original_cs5t);
        if (original_connection == nullptr)
        {
            // packet is the first packet in the original pcap for packet's connection
            // Since it's the first, we TcpConnection object has not been made yet.
            // since it's the first, there is nothing to compare so the result of the function is true
            return true;
        }
        if (original_connection->protocol() != IPPROTO_UDP)
            return true;

        bool result = received_expected_udp_connection((UdpConnection *)original_connection);

        if (!result)
            if (debug_output) std::cout << "[+]\tExpected UDP: result = " << result << std::endl;

        return result;
    }
}

bool PcapReplayNetworkStack::received_expected_udp_connection(UdpConnection *original_connection)
{
    UdpConnection *replayed_connection = (UdpConnection *)convert_Connection(original_connection, true);

    if (replayed_connection == nullptr)
        return false;

    if (!original_connection->updates() && !replayed_connection->updates())
    {
        try
        {
            return received_expected_cache.at(original_connection);
        }
        catch (const std::out_of_range& oor)
        {}
    }

    bool result = true;
    bool done = false;

    if (config.tx_event_udp_application)
    {
        // config.tx_event_udp_data should also be on since its our fall back method

        // If received expected application data -> dont check tcp data bytes
        // If not received expected application data -> fall back to checking transport data bytes
        if (received_expected_application(original_connection))
        {
            result = true;
            done = true;
        }
        else
        {
            // Fallback in case we don't know the application protocol yet / can't handle the application proto
            if (config.tx_event_udp_data)
            {
                result = received_expected_transport_data(original_connection); // verifies data at the byte level
                done = true;
            }
            else
            {
                // This kind of assumes that we have implemented all application level protocols in the pcap
                // Otherwise we might get stuck here if we are unable to identify the application with the first data segment
                // It is suggested to the user that config.tx_event_tcp_data should be enabled anyways as a fallback
                result = false;
                done = true;
                // Should this be return true to avoid this? (Would case HTTP responses to be sent early though)
            }
        }
    }
    if (!done && config.tx_event_udp_data)
    {
        if (!received_expected_transport_data(original_connection))
            result = false; // verifies data at the byte level
    }

    received_expected_cache[original_connection] = result;
    original_connection->clear_updates();
    replayed_connection->clear_updates();

    return result;
}
