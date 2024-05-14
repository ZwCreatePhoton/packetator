#include <iostream>
#include <optional>

#include "PcapReplayNetworkStack/pcap_replay_network_stack.h"
#include "utils.h"

using std::pair;


PcapReplayNetworkStack::PcapReplayNetworkStack(NetworkDevice &networkDevice, PcapReplayNetworkStackConfig &config) : TCPIPNetworkStack(networkDevice), config(config), pcap_ip_map(config.pcap_ip_map)
{
    runtime_arp_reponse_wait = config.wait_for_arp_response;
    if (config.l3_device)
    {
        init_route_table();
    }
    preprocess_pcap_packets(config.packets);
    original_ipv4defragmenter_tx->SetCallback([&](Tins::Packet p){process_next_original_packet_ip(p);});
    original_ipv4defragmenter_rx->SetCallback([&](Tins::Packet p){process_next_original_packet_ip(p);});
    original_ipv4defragmenter_other->SetCallback([&](Tins::Packet p){process_next_original_packet_ip(p);});
    ipv4defragmenter_tx->SetCallback([&](Tins::Packet p){update_output(p);});
    original_ipv6defragmenter_tx->SetCallback([&](Tins::Packet p){process_next_original_packet_ip(p);});
    original_ipv6defragmenter_rx->SetCallback([&](Tins::Packet p){process_next_original_packet_ip(p);});
    original_ipv6defragmenter_other->SetCallback([&](Tins::Packet p){process_next_original_packet_ip(p);});
    ipv6defragmenter_tx->SetCallback([&](Tins::Packet p){update_output(p);});
}

void PcapReplayNetworkStack::init()
{
    if (config.take_packet_capture) start_packet_capture();
    TCPIPNetworkStack::init();
}

void PcapReplayNetworkStack::init_route_table()
{
    route_table.clear();

    if (!netdev.gateway.empty())
    {
        bool is_ipv4 = netdev.ip_address.find('.') != std::string::npos;
        std::string dst = is_ipv4 ? "0.0.0.0" : "0:0:0:0:0:0:0:0";
        std::string mask = is_ipv4 ? "0.0.0.0" : "0:0:0:0:0:0:0:0";
        route_table.add(dst, netdev.gateway, mask, RT_GATEWAY, 0);
    }
}

void PcapReplayNetworkStack::preprocess_pcap_packets(std::vector <Tins::Packet> * pcap_packets)
{
    verify_pcap_ip_map();
//    verify_pcap_packets(pcap_packets);
    pcap_start_packet = pcap_packets->at(0);
    filter_pcap_packets(pcap_packets); // fills this->packets
    preprocess_pcap_packets_ip();
    populate_dips();
}

void PcapReplayNetworkStack::filter_pcap_packets(std::vector <Tins::Packet> *pcap_packets)
{
    for (auto packet : *pcap_packets)
    {
        auto addresses = get_source_dest_addresses(packet);
        std::string src_ip = convert_ip_address(addresses.first, true);
        std::string dst_ip = convert_ip_address(addresses.second, true);

        // Keep packets from us
        if (src_ip == netdev.ip_address)
        {
            packets.push_back(packet);
        }
            // Keep packets destined for us
            // TODO: keep multicast as well ?
        else if (dst_ip == netdev.ip_address)
        {
            packets.push_back(packet);
        }
            //
        else
        {
            continue;
        }
    }
}

void PcapReplayNetworkStack::populate_dips()
{
    // add all the destination IP addresses to the set: "dips"
    for (auto packet : packets)
    {
        auto addresses = get_source_dest_addresses(packet);
        std::string src_ip = convert_ip_address(addresses.first, true);
        std::string dst_ip = convert_ip_address(addresses.second, true);
        if (src_ip == netdev.ip_address)
        {
            dips.insert(dst_ip);
        }
    }
}

void PcapReplayNetworkStack::verify_pcap_ip_map()
{
    // Checks if pcap_map is bijective (one-to-one) so that we can do reverse look ups of IP addresses
    if (!is_bijective(pcap_ip_map))
    {
        std::cout << "[!]\tFATAL: pcap_ip_map is not bijective! (one-to-one)" << std::endl;
        exit(1);
    }

    // Warn if this network stack's IP address is missing from pcap_ip_map
    std::_Rb_tree_const_iterator<std::pair<const std::basic_string<char>, std::basic_string<char>>> it = this->pcap_ip_map.begin();
    bool contains_ip = false;
    for (std::pair<std::string, std::string> element : pcap_ip_map)
    {
        auto ip_address = element.second;
        if (ip_address == netdev.ip_address)
        {
            contains_ip = true;
            break;
        }
    }
    if (!contains_ip)
    {
        std::cout << "[!]\tFATAL: IP address " << netdev.ip_address << " is not in pcap_ip_map!" << std::endl;
        exit(1);
    }
}

void PcapReplayNetworkStack::verify_pcap_packets(std::vector <Tins::Packet> *pcap_packets)
{
    for (auto packet : *pcap_packets)
    {
        if (packet.pdu()->find_pdu<Tins::IP>() == nullptr && packet.pdu()->find_pdu<Tins::IPv6>() == nullptr)
        {
            std::cout << "[!]\tFATAL: PDU other than Tins::IP or Tins::IPv6 in packets vector." << std::endl;
            exit(1);
        }
    }
}

void PcapReplayNetworkStack::process_next_original_packet(Tins::Packet &packet)
{
    process_next_original_packet_ip_possible_fragments(packet);
}

void PcapReplayNetworkStack::tx_loop()
{
    // Should I move this out of tx_loop so that each host will be better sync with each other?
    // Don't know if the variation in time it takes for this is enough to get hosts out of sync.
    if (config.early_address_resolution)
    {
        if (config.early_address_resolution_ping) perform_early_address_resolution();
        if (config.early_arp) perform_early_arp();
        if (config.early_garp_request) perform_early_garp_request();
        if (config.early_garp_reply) perform_early_garp_reply();
        if (config.early_unsolicited_na) perform_early_unsolicited_na();
    }

    std::optional<int> last_tx_packet_index;
    tx_time = Clock::now();
    rx_time = Clock::now();

    int handled_index = packets_index - 1;
    while (packets_index < packets.size() && ((handled_index == -1) || !exit_tx_loop_early()))
    {
        if (packets_index != handled_index)
        {
            process_next_original_packet(packets[packets_index]);
            handled_index++;
        }

        handle_rx_queue(); // update what we received

        //State:T
        if (is_tx_packet(packets_index))
        {
            auto packet = packets[packets_index];

            // rewrite packet
            rewrite_packet(packet);

            // transmit packet delays
            if (config.honor_time_delta_previous_tx)
            {
                Clock::duration time_delta_to_wait = std::chrono::seconds(0);
                auto &last_tx_packet = last_tx_packet_index.has_value() ? packets[last_tx_packet_index.value()] : pcap_start_packet;
                Clock::duration time_delta_previous_tx =    (std::chrono::seconds(packet.timestamp().seconds()) + std::chrono::microseconds(packet.timestamp().microseconds())) -
                                                            (std::chrono::seconds(last_tx_packet.timestamp().seconds()) + std::chrono::microseconds(last_tx_packet.timestamp().microseconds()));
                time_delta_to_wait = time_delta_previous_tx - (Clock::now() - tx_time);
                if (time_delta_to_wait > config.honor_time_delta_min_microseconds)
                    std::this_thread::sleep_for(time_delta_to_wait);
            }

            // transmit packet
            bool is_ipv4 = packet.pdu()->find_pdu<Tins::IP>() != nullptr;
            if (is_ipv4)
            {
                ipv4defragmenter_tx->ProcessPacket(packet);
            }
            else
            {
                ipv6defragmenter_tx->ProcessPacket(packet);
            }
            output_packet(packet);
            tx_time = Clock::now();
            last_tx_packet_index = packets_index;
            packets_index++;
        }
            //State:R
        else // is a rx packet
        {
            if (std::find(expected.begin(), expected.end(), packets_index) == expected.end()) // if we have yet to push packets[packets_index] into expected
            {
                // Had trouble with this conditional being hit sometimes when "expected" was of vector of Tins::Packet
                // But it works when "expected" is a vector of int.
                // Maybe something to do with "==" operator for 2 Tins::Packet objects?
                expected.push_back(packets_index); // update what we expect to receive
            }

            // State: R_
            if (packets_index == packets.size() - 1) // last packet in the pcap
            {
                packets_index++; // will cause while loop condition to become false -> ends replaying of packets for this host
            }
                // State: RR
            else if (!is_tx_packet(packets_index+1))
            {
                packets_index++;
            }
                //State: RT
            else
            {
                if (received_expected())
                {
                    expected.clear();
                    actual.clear();
                    packets_index++;
                }
            }
        }
        usleep(100);
    }

    while (tx_time != std::chrono::system_clock::time_point::min() &&
           (std::chrono::system_clock::now() - tx_time) < config.timeout_duration &&
           rx_time != std::chrono::system_clock::time_point::min() &&
           (std::chrono::system_clock::now() - rx_time) < config.timeout_duration &&
           packets_index >= packets.size() &&
           !result())
    {
        std::this_thread::yield();
        usleep(1000);
    }
}

bool PcapReplayNetworkStack::exit_tx_loop_early()
{
    if (!enable_tx_loop) return true;
    if (config.stop_on_timeout)
    {
        int last_rx_index = packets_index-1;
        for (; last_rx_index > 0; last_rx_index--)
        {
            if (is_rx_packet(last_rx_index))
                break;
        }
        int last_tx_index = packets_index-1;
        for (; last_tx_index > 0; last_tx_index--)
        {
            if (is_tx_packet(last_tx_index))
                break;
        }
        std::chrono::duration og_time_delta_last_tx = std::chrono::seconds(packets[packets_index].timestamp().seconds()) + std::chrono::microseconds(packets[packets_index].timestamp().microseconds()) - std::chrono::seconds(packets[last_tx_index].timestamp().seconds()) + std::chrono::microseconds(packets[last_tx_index].timestamp().microseconds());
        std::chrono::duration og_time_delta_last_rx = std::chrono::seconds(packets[packets_index].timestamp().seconds()) + std::chrono::microseconds(packets[packets_index].timestamp().microseconds()) - std::chrono::seconds(packets[last_rx_index].timestamp().seconds()) + std::chrono::microseconds(packets[last_rx_index].timestamp().microseconds());
        if (tx_time != std::chrono::system_clock::time_point::min() &&
            (std::chrono::system_clock::now() - tx_time) > (config.timeout_duration + og_time_delta_last_tx) &&
            rx_time != std::chrono::system_clock::time_point::min() &&
            (std::chrono::system_clock::now() - rx_time) > (config.timeout_duration + og_time_delta_last_rx))
        {
            // It has been more than config.timeout_duration since the we have last transmitted a packet
            std::cout << "[+]\tTimed out waiting for the expected!"<< std::endl;
            return true;
        }
    }
    if (config.tx_event_transport && exit_tx_loop_early_tcp()) return true;
    return false;
}

void PcapReplayNetworkStack::rewrite_packet(Tins::Packet &packet)
{
    rewrite_packet_ip(packet);
}

// Criteria that must be met before we transmit the next packet
bool PcapReplayNetworkStack::received_expected()
{
    return received_expected_ip();
}

void PcapReplayNetworkStack::handle_rx_packet(Tins::Packet packet)
{
    auto &frame = packet.pdu()->rfind_pdu<Tins::EthernetII>();

    switch (frame.inner_pdu()->pdu_type())
    {
        case Tins::PDU::IP:
            handle_ipv4(packet);
            break;
        case Tins::PDU::IPv6:
        {
            handle_ipv6(packet);
            break;
        }
        default:
            break;
    }

    actual.push_back(packet);
    rx_time = Clock::now();
}

void PcapReplayNetworkStack::handle_rx_queue()
{
    std::lock_guard<std::mutex> lg(rx_queue_mutex);
    while (!rx_queue.empty())
    {
        handle_rx_packet(rx_queue.front());
        rx_queue.pop();
    }
}

// This is run in a separate thread
void PcapReplayNetworkStack::handle_frame(Tins::Packet &packet)
{
    auto &frame = packet.pdu()->rfind_pdu<Tins::EthernetII>();

    switch (frame.inner_pdu()->pdu_type())
    {
        case Tins::PDU::IP:
            if (config.early_address_resolution_ping && is_early_arp_packet_response(packet))
                return;
            break;
        case Tins::PDU::IPv6:
        {
            // check if NDP
            auto &ip6 = packet.pdu()->rfind_pdu<Tins::IPv6>();
            if(ip6.inner_pdu()->pdu_type() == Tins::PDU::ICMPv6)
            {
                handle_icmpv6(packet); // NDP
                return;
            }
            break;
        }
        case Tins::PDU::ARP:
        {
            handle_arp(packet);
            return;
        }
        default:
            break;
    }

    std::lock_guard<std::mutex> lg(rx_queue_mutex);
    rx_queue.push(packet);
}

bool PcapReplayNetworkStack::result()
{
    handle_rx_queue();
    bool old_tx_event_udp_all_connections = config.tx_event_udp_all_connections;
    bool old_tx_event_tcp_all_connections = config.tx_event_tcp_all_connections;
    config.tx_event_udp_all_connections = true;
    config.tx_event_tcp_all_connections = true;
    bool result = packets_index == packets.size() && received_expected();
    config.tx_event_udp_all_connections = old_tx_event_udp_all_connections;
    config.tx_event_tcp_all_connections = old_tx_event_tcp_all_connections;
    return result;
}
