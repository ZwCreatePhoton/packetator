#include "tins/tins.h"

#pragma once

namespace Tuple
{
    struct FiveTuple
    {
        std::string source_ip;
        uint16_t source_port;
        std::string destination_ip;
        uint16_t destination_port;
        uint8_t protocol;
    };

    struct ClientServerFiveTuple
    {
        std::string client_ip;
        uint16_t client_port;
        std::string server_ip;
        uint16_t server_port;
        uint8_t protocol;
    };

    struct ClientServerFourTuple
    {
        std::string client_ip;
        std::string server_ip;
        uint16_t server_port;
        uint8_t protocol;
    };

    static FiveTuple
    ClientServerFiveTuple_to_FiveTuple(const ClientServerFiveTuple &cs5t, bool src_is_server)
    {
        return FiveTuple {
                src_is_server ? cs5t.server_ip : cs5t.client_ip,
                src_is_server ? cs5t.server_port : cs5t.client_port,
                src_is_server ? cs5t.client_ip : cs5t.server_ip,
                src_is_server ? cs5t.client_port : cs5t.server_port,
                cs5t.protocol
        };
    }

    static ClientServerFiveTuple
    FiveTuple_to_ClientServerFiveTuple(const FiveTuple &fiveTuple, bool src_is_server)
    {
        return ClientServerFiveTuple {
                src_is_server ? fiveTuple.destination_ip : fiveTuple.source_ip,
                src_is_server ? fiveTuple.destination_port : fiveTuple.source_port,
                src_is_server ? fiveTuple.source_ip : fiveTuple.destination_ip,
                src_is_server ? fiveTuple.source_port : fiveTuple.destination_port,
                fiveTuple.protocol
        };
    }

    static std::unique_ptr<ClientServerFourTuple>
    ClientServerFiveTuple_to_ClientServerFourTuple(const ClientServerFiveTuple &cs5t)
    {
        return std::make_unique<ClientServerFourTuple>(
                ClientServerFourTuple{
                        cs5t.client_ip,
                        cs5t.server_ip,
                        cs5t.server_port,
                        cs5t.protocol
                }
        );
    }

// client_port will be set to 0
    static std::unique_ptr<ClientServerFiveTuple>
    ClientServerFourTuple_to_ClientServerFiveTuple(const ClientServerFourTuple &cs4t)
    {
        return std::make_unique<ClientServerFiveTuple>(
                ClientServerFiveTuple{
                        cs4t.client_ip,
                        0,
                        cs4t.server_ip,
                        cs4t.server_port,
                        cs4t.protocol
                }
        );
    }

    static std::unique_ptr<FiveTuple> packet_to_FiveTuple(const Tins::Packet& packet)
    {
        FiveTuple cs5t;

        Tins::PDU *transport;
        auto *ip4 = packet.pdu()->find_pdu<Tins::IP>();
        if(ip4 != nullptr)
        {
            cs5t.source_ip = ip4->src_addr().to_string();
            cs5t.destination_ip = ip4->dst_addr().to_string();
            transport = ip4->inner_pdu();
        }
        else
        {
            auto *ip6 = packet.pdu()->find_pdu<Tins::IPv6>();
            cs5t.source_ip = ip6->src_addr().to_string();
            cs5t.destination_ip = ip6->dst_addr().to_string();
            transport = ip6->inner_pdu();
        }
        switch (transport->pdu_type())
        {
            case Tins::PDU::TCP:
                cs5t.source_port = ((Tins::TCP *)transport)->sport();
                cs5t.destination_port = ((Tins::TCP *)transport)->dport();
                cs5t.protocol = IPPROTO_TCP;
                break;
            case Tins::PDU::UDP:
                cs5t.source_port = ((Tins::UDP *)transport)->sport();
                cs5t.destination_port = ((Tins::UDP *)transport)->dport();
                cs5t.protocol = IPPROTO_UDP;
                break;
            default:
                return nullptr;
        }

        return std::make_unique<FiveTuple>(cs5t);
    }
}
