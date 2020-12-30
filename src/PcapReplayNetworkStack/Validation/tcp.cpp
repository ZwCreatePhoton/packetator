#include <iostream>

#include "PcapReplayNetworkStack/pcap_replay_network_stack.h"
#include "utils.h"

bool PcapReplayNetworkStack::received_expected_tcp()
{
    if (config.tx_event_tcp_all_connections)
    {
        std::vector<Connection *> *original_connections = original_connection_table.all();
        for (auto original_connection : *original_connections)
        {
            if (original_connection->protocol() == IPPROTO_TCP)
            {
                if (!received_expected_tcp_connection((TcpConnection *)original_connection))
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
        // Find the TcpConnection object relevant for packets[packet_index + 1] (the next TX packet)
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
        if (original_connection->protocol() != IPPROTO_TCP)
            return true;

        bool result = received_expected_tcp_connection((TcpConnection *)original_connection);

        if (result)
            if (debug_output) std::cout << "[+]\tExpected TCP: result = " << result << std::endl;

        return result;
    }
}

bool PcapReplayNetworkStack::received_expected_tcp_connection(TcpConnection *original_connection)
{
    TcpConnection *replayed_connection = (TcpConnection *)convert_Connection(original_connection, true);

    if (replayed_connection == nullptr)
        return false;

//    if (!original_connection->updates() && !replayed_connection->updates())
//    {
//        try
//        {
//            return received_expected_cache.at(original_connection);
//        }
//        catch (const std::out_of_range& oor)
//        {}
//    }

    bool result = true;
    bool done = false;

    if (config.tx_event_tcp_state)
    {
        // Conditions that must be met:
        // 1. original server state is equal to or less than the replayed server state
        // 2. original client state is equal to or less than the replayed client state

        bool substate = (
                original_connection->server_flow().state <= replayed_connection->server_flow().state &&
                original_connection->client_flow().state <= replayed_connection->client_flow().state );
        result = substate;
        if (!result)
        {
            if (debug_output) std::cout << "[+]\tExpected TCP Connection: tcp state mismatch" << std::endl;
            result = false;
            done = true;
        }
    }

    if (!done && config.tx_event_tcp_application)
    {
        // config.tx_event_tcp_data should also be on since its our fall back method

        // Application layer data verification if enabled.
        // maybe this is where handling of pure ACKs and data segments should diverge since ACK is a TCP construct
        // If received expected application data -> dont check tcp data bytes
        // If not received expected application data -> fall back to checking tcp data bytes

        // Need to check state because tx_event_tcp_application received_expected_application will always false initially and so will received_expected_tcp_data
        // So we would get in a stuck false loop mid-handshake when the fallback tx_event_tcp_data = false since the back up to the fallback is "return false" ...
        if (    original_connection->server_flow().state != TcpFlow::CLOSED1 &&
                original_connection->server_flow().state != TcpFlow::LISTEN &&
                original_connection->server_flow().state != TcpFlow::SYN_SENT &&
                original_connection->server_flow().state != TcpFlow::SYN_RECEIVED &&
                original_connection->client_flow().state != TcpFlow::CLOSED1 &&
                original_connection->client_flow().state != TcpFlow::LISTEN &&
                original_connection->client_flow().state != TcpFlow::SYN_SENT &&
                original_connection->client_flow().state != TcpFlow::SYN_RECEIVED
                )
        {
            if (received_expected_application(original_connection))
            {
                result = true; // probably wouldn't want to continue checking more TCP stuff
                done = true;
            }
            else
            {
                // Fallback incase we don't know the application protocol yet / can't handle the application proto
                if (config.tx_event_tcp_data)
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
                    // Should this be return true to avoid this? (Would case HTTP response to be sent early though)
                }
            }
        }
    }
    if (!done && config.tx_event_tcp_data)
    {
        if (!received_expected_transport_data(original_connection))
        {
            result = false; // verifies data at the byte level
            done = true;
        }
    }
    if (!done && config.tx_event_tcp_segment_count)
    {
        // expected count (The number of segments in the vector "expected" that belong to original_connection)
        int expected_count = 0;
        for (auto index : expected)
        {
            Tins::Packet &packet = packets[index];
            if (packet.pdu() == nullptr) continue;
            auto tcp = packet.pdu()->find_pdu<Tins::TCP>();
            if (tcp == nullptr) continue;
            std::unique_ptr<Tuple::FiveTuple> fivetuple = Tuple::packet_to_FiveTuple(packet);
            Tuple::ClientServerFiveTuple cs5t = FiveTuple_to_ClientServerFiveTuple(*fivetuple, true);
            if (
                    original_connection->client_port() == cs5t.client_port &&
                    original_connection->server_port() == cs5t.server_port &&
                    original_connection->client_ip() == cs5t.client_ip &&
                    original_connection->server_ip() == cs5t.server_ip )
            {
                expected_count++;
            }
        }

        // actual count (The number of segments in the vector "actual" that belong to the replayed connection corresponding to original_connection)
        int actual_count = 0;
        TcpConnection *replayed_connection = (TcpConnection *)convert_Connection(original_connection, true);
        if (replayed_connection != nullptr)
        {
            for (auto &packet : actual)
            {
                if (packet.pdu() == nullptr) continue;
                auto tcp = packet.pdu()->find_pdu<Tins::TCP>();
                if (tcp == nullptr) continue;
                std::unique_ptr<Tuple::FiveTuple> fivetuple = Tuple::packet_to_FiveTuple(packet);
                Tuple::ClientServerFiveTuple cs5t = FiveTuple_to_ClientServerFiveTuple(*fivetuple, false);
                if (
                        replayed_connection->client_port() == cs5t.client_port &&
                        replayed_connection->server_port() == cs5t.server_port &&
                        replayed_connection->client_ip() == cs5t.client_ip &&
                        replayed_connection->server_ip() == cs5t.server_ip )
                {
                    actual_count++;
                }
            }
        }
        // when replayed_connection is not found, actual_count is zero

        result = expected_count == actual_count;
        done = true;
    }

    received_expected_cache[original_connection] = result;
    original_connection->clear_updates();
    replayed_connection->clear_updates();

    return result;
}

