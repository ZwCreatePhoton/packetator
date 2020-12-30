#include <iostream>

#include "TCPIPNetworkStack/tcp_ip_network_stack.h"

#define ARP_ETHERNET    0x0001
#define ARP_IPV4        0x0800
#define ARP_REQUEST     0x0001
#define ARP_REPLY       0x0002

void TCPIPNetworkStack::handle_arp_request(Tins::Packet &packet)
{
    auto &arp = packet.pdu()->rfind_pdu<Tins::ARP>();

//    std::cout << "[+]\tARP request: sender hardware address: " << arp->sender_hw_addr() << std::endl;
//    std::cout << "[+]\tARP request: sender ip address: " << arp->sender_ip_addr() << std::endl;
//    std::cout << "[+]\tARP request: target hardware address: " << arp->target_hw_addr() << std::endl;
//    std::cout << "[+]\tARP request: target ip address: " << arp->target_ip_addr() << std::endl;

    if (arp.target_ip_addr().to_string() == netdev.ip_address)
    {
        send_arp_reply(arp.sender_ip_addr().to_string(), arp.target_ip_addr().to_string(), arp.sender_hw_addr().to_string(), netdev.mac_address);
//        std::cout << "[+]\tARP request: sent a reply to the request! " << std::endl;
    }
    else
    {
        // This arp request is not for us
        std::cout << "[+]\tARP request: request was not for us" << std::endl;
        return; // drop frame
    }
}

void TCPIPNetworkStack::handle_arp_reply(Tins::Packet &packet)
{
    auto &arp = packet.pdu()->rfind_pdu<Tins::ARP>();

//    std::cout << "[+]\tARP reply: sender hardware address: " << arp->sender_hw_addr() << std::endl;
//    std::cout << "[+]\tARP reply: sender ip address: " << arp->sender_ip_addr() << std::endl;
//    std::cout << "[+]\tARP reply: target hardware address: " << arp->target_hw_addr() << std::endl;
//    std::cout << "[+]\tARP reply: target ip address: " << arp->target_ip_addr() << std::endl;

    if (arp.target_ip_addr().to_string() == netdev.ip_address)
    {
        ;
    }
    else
    {
        // This arp reply is not for us
        std::cout << "ARP reply: reply was not for us" << std::endl;
        return; // drop frame
    }
}

void TCPIPNetworkStack::handle_arp(Tins::Packet &packet)
{
    auto &arp = packet.pdu()->rfind_pdu<Tins::ARP>();

//    std::cout << "[+]\tSender HW addr: " << arp->sender_hw_addr() << std::endl;

    // check HW type
    if (arp.hw_addr_format() == ARP_ETHERNET)
    {
//        std::cout << "[+]\tARP: we support this hardware type :)" << std::endl;
    }
    else
    {
        std::cout << "[!]\tARP: Unsupported hardware type!" << std::endl;
        return; // drop frame
    }

    // check protocol type
    if (arp.prot_addr_format() == ARP_IPV4)
    {
//        std::cout << "[+]\tARP: we support this protocol type :)" << std::endl;
    }
    else
    {
        std::cout << "[!]\tARP: Unsupported protocol type!" << std::endl;
        return; // drop frame
    }

    neighbor_table.update(arp.sender_ip_addr().to_string(), arp.sender_hw_addr().to_string());
    std::cout << "[+]\tARP: Inserted or updated entry into the ARP table" << std::endl;
    switch(arp.opcode())
    {
        case ARP_REQUEST:
            handle_arp_request(packet);
            break;
        case ARP_REPLY:
            handle_arp_reply(packet);
            break;
        default:
            std::cout << "[!]\tARP: Unsupported opcode! (" << arp.opcode() << ")" << std::endl;
            return; // drop frame
    }
}

void TCPIPNetworkStack::send_arp_request(std::string target_ip, std::string source_ip, std::string source_mac)
{
    Tins::EthernetII frame = Tins::ARP::make_arp_request(target_ip, source_ip, source_mac);
    netdev.transmit(frame);
}

void TCPIPNetworkStack::send_arp_reply(std::string target_ip, std::string source_ip, std::string target_mac, std::string source_mac)
{
    Tins::EthernetII arp_reply_frame = Tins::ARP::make_arp_reply(target_ip, source_ip, target_mac, source_mac);
    netdev.transmit(arp_reply_frame);
}

