#include <iostream>

#include <unistd.h>

#include "TCPIPNetworkStack/tcp_ip_network_stack.h"


void TCPIPNetworkStack::output_packet(Tins::Packet &packet, std::string dest_ip, const std::string& source_ip)
{
    if (error_on_sip_mismatch && source_ip != netdev.ip_address)
    {
        std::cout << "[!!]\toutput_ipv4: error: source ip address mismatch between packet to transmit (" << source_ip << ") and netdev's IP (" << netdev.ip_address << ")" << std::endl;
        exit(1);
    }

    std::unique_ptr<Tins::PDU> pdu;
    auto *ip4p = packet.pdu()->find_pdu<Tins::IP>();
    auto *ip6p = packet.pdu()->find_pdu<Tins::IPv6>();
    if (ip4p == nullptr && ip6p == nullptr)
    {
        if (dest_ip.find('.') != std::string::npos) // ipv4
        {
            Tins::IP ip = Tins::IP(dest_ip, source_ip) / *packet.pdu();
            pdu = std::unique_ptr<Tins::PDU>(ip.clone());
        }
        else
        {
            Tins::IPv6 ip6 = Tins::IPv6(dest_ip, source_ip) / *packet.pdu();
            ip6.hop_limit(128);
            pdu = std::unique_ptr<Tins::PDU>(ip6.clone());
        }
    }
    else
    {
        if (ip4p != nullptr)
        {
            pdu = std::unique_ptr<Tins::PDU>(ip4p->clone());
        }
        else
        {
            pdu = std::unique_ptr<Tins::PDU>(ip6p->clone());
        }
    }

    // perform a route lookup for the intended host
    RouteTableEntry *route_table_entry = route_table.lookup(dest_ip);
    if (!route_table_entry)
    {
        std::cout << "[!]\tIP: No route found for " << dest_ip << std::endl;
        return;
    }

    if (route_table_entry->flags & RT_GATEWAY)
    {
        dest_ip = route_table_entry->gateway;
    }

    //dest_ip should now be the ip address of the host we're sending to (not necessarily the destination ip of the packet)

    // perform arp lookup for the destination address from the route lookup
    std::string dmac = neighbor_table.lookup(dest_ip);
    std::string smac = netdev.mac_address;

    // No neighbor entry exists so we must perform address resolution
    if (dmac.empty())
    {
        auto resolve_then_send = [this](std::string _daddr, std::string _src_addr, std::string _smac, std::unique_ptr<Tins::PDU> _packet)
        {
            std::cout << "[+]\tPerforming address resolution in a new thread!" << std::endl;

            bool is_ipv4 = _daddr.find('.') != std::string::npos;
            if (is_ipv4)
                send_arp_request(_daddr, _src_addr, _smac);
            else
            {
                send_ndp_neighbor_solicitation(_daddr, _src_addr, _smac);
            }

            if (runtime_arp_reponse_wait)
            {
                std::string _dmac;
                int limit = runtime_arp_reponse_wait_limit; // 1 second total limit
                const int sleep_duration = 10000; // units of microseconds. // == 10 millisecond
                while (_dmac.empty())
                {
                    _dmac = neighbor_table.lookup(_daddr);
                    usleep(sleep_duration);
                    limit = limit - 10;
                    if (limit <= 0)
                    {
                        std::cout << "[!]\tWe did not receive an ARP/NDP response in time!" << std::endl;
                        return;
                    }
                }

                // If we get a seg fault it's because the destructor of frame take control of the pointer so we should change back to using plain pointers
                Tins::EthernetII frame = Tins::EthernetII(_dmac, _smac) / *_packet;
                netdev.transmit(frame);
            }
        };

        std::thread t = std::thread(resolve_then_send, dest_ip, source_ip, smac, std::move(pdu));
        t.detach();
        usleep(500); // Small chance of landing here twice in a row -> double ARP + chance of sending out of order. //TODO: Protect against this properally
        return;
    }

    Tins::EthernetII frame = Tins::EthernetII(dmac, smac) / *pdu;
    netdev.transmit(frame);
}

void TCPIPNetworkStack::output_packet(Tins::Packet &packet, std::string dest_ip)
{
    return output_packet(packet, dest_ip, netdev.ip_address);
}

void TCPIPNetworkStack::output_packet(Tins::Packet &packet)
{
    auto *ip = packet.pdu()->find_pdu<Tins::IP>();
    if (ip != nullptr)
    {
        return output_packet(packet, ip->dst_addr().to_string(), ip->src_addr().to_string());
    }
    else
    {
        auto *ip6 = packet.pdu()->find_pdu<Tins::IPv6>();
        if (ip6 != nullptr)
        {
            return output_packet(packet, ip6->dst_addr().to_string(), ip6->src_addr().to_string());
        }
        else
        {
            auto *frame = packet.pdu()->find_pdu<Tins::EthernetII>();
            if (frame != nullptr)
            {
                std::unique_ptr<Tins::PDU> frame_copy = std::unique_ptr<Tins::PDU>(frame->clone());
                netdev.transmit(*frame_copy);
            }
            else
            {
                std::cout << "[!]\tIP: Tried to send out a non-IP pdu without the destination ip " << std::endl;
                exit(1);
            }
        }
    }
}
