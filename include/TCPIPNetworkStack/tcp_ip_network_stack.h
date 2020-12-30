#include <type_traits>
#pragma once

#include <iostream>
#include <unistd.h>

#include <TCPIPNetworkStack/Internet/neighbor_table.h>
#include <TCPIPNetworkStack/Internet/route_table.h>
#include <TCPIPNetworkStack/network_stack.h>
#include <TCPIPNetworkStack/Transport/connection_table.h>
#include <TCPIPNetworkStack/Transport/TCP/tcp_connection.h>
#include <TCPIPNetworkStack/Transport/UDP/udp_connection.h>
#include <TCPIPNetworkStack/Internet/IPv6/IPv6Defragmenter.h>
#include "TCPIPNetworkStack/Internet/IP/IPv4Defragmenter.h"


class TCPIPNetworkStack : public NetworkStack
{
    public:
        explicit TCPIPNetworkStack(NetworkDevice&);

    public:
        void init() override;
        void handle_frame(Tins::Packet &packet) override;

        void output_frame(Tins::Packet &packet);

        // arp
        NeighborTable neighbor_table;
        void handle_arp(Tins::Packet &packet);
        void handle_arp_request(Tins::Packet &packet);
        void handle_arp_reply(Tins::Packet &packet);
        void send_arp_request(std::string target_ip, std::string source_ip, std::string source_mac);
        void send_arp_reply(std::string target_ip, std::string source_ip, std::string target_mac, std::string source_mac);

        // ip
        void output_packet(Tins::Packet &packet);
        void output_packet(Tins::Packet &packet, std::string dest_ip, const std::string& source_ip);
        void output_packet(Tins::Packet &packet, std::string dest_ip);
        std::unique_ptr<Defragmenter> ipv4defragmenter_rx = std::make_unique<IPv4Defragmenter>();
        std::unique_ptr<Defragmenter> ipv6defragmenter_rx = std::make_unique<IPv6Defragmenter>();
        std::unique_ptr<Defragmenter> ipv4defragmenter_tx = std::make_unique<IPv4Defragmenter>();
        std::unique_ptr<Defragmenter> ipv6defragmenter_tx = std::make_unique<IPv6Defragmenter>();

        // ipv4
        RouteTable route_table;
        bool runtime_arp_reponse_wait = true; // Some DUT ARP implementations will drop the IP packet when address resolution has to be performed so that the stack doesn't have to wait for a resume; assume that upper layers will handle the loss.
        int runtime_arp_reponse_wait_limit = 1000; // units = milliseconds
        bool error_on_sip_mismatch = true;
        virtual void handle_ipv4(Tins::Packet &packet);
        virtual void handle_ipv4_nonfragment(Tins::Packet &packet);
        virtual void handle_ipv4_fragment(Tins::Packet &packet);

        // icmp
        bool enable_ping_replay = true;
        virtual void handle_icmp(Tins::Packet &packet);
        void handle_icmp_echo_request(Tins::Packet &packet);
        void handle_icmp_echo_reply(Tins::Packet &packet);
        void handle_icmp_dest_unreachable(Tins::Packet &packet);
        void send_icmp_echo_request(const std::string &target_ip);
//        void send_icmp_echo_reply();

        // ipv6
        virtual void handle_ipv6(Tins::Packet &packet);
        virtual void handle_ipv6_nonfragment(Tins::Packet &packet);
        virtual void handle_ipv6_fragment(Tins::Packet &packet);

        // icmpv6
        virtual void handle_icmpv6(Tins::Packet &packet);
        void handle_icmpv6_echo_request(Tins::Packet &packet);
        void handle_icmpv6_echo_reply(Tins::Packet &packet);
        void handle_icmpv6_dest_unreachable(Tins::Packet &packet);
        void send_icmpv6_echo_request(const std::string &target_ip);

        // ndp
        void handle_ndp_neighbor_solicitation(Tins::Packet &packet);
        void handle_ndp_neighbor_advertisement(Tins::Packet &packet);
        void send_ndp_neighbor_solicitation(std::string target_ip, std::string source_ip, std::string source_mac);
        void send_ndp_neighbor_advertisement(std::string dest_ip, std::string source_ip, std::string target_mac, std::string source_mac, bool solicited, bool override);
        void handle_ndp_router_solicitation(Tins::Packet &packet);
        void handle_ndp_router_advertisement(Tins::Packet &packet);
        void handle_ndp_redirect_message(Tins::Packet &packet);

        // Transport
        ConnectionTable connection_table{};

        // tcp
        std::vector<uint16_t> listening_tcp_ports{};
        virtual void handle_tcp(Tins::Packet &packet);
        virtual void handle_tcp_connection_attempt(Tins::Packet &packet, TcpConnection &connection);
        virtual void handle_tcp_data_ack(Tins::Packet &packet, TcpConnection &connection); // Sends out an ACK in response to incoming data segments
        virtual void handle_tcp_connection_termination(Tins::Packet &packet, TcpConnection &connection);


        // udp
        std::vector<uint16_t> listening_udp_ports{};
        virtual void handle_udp(Tins::Packet &packet);


        // IP utils
        static Tins::Packet packetize(Tins::PDU &pdu, const std::string& destination_ip, const std::string& source_ip);

        // Tuple utils
        Tuple::ClientServerFiveTuple FiveTuple_to_ClientServerFiveTuple(const Tuple::FiveTuple& ft);
        virtual bool is_source_server(const Tuple::FiveTuple& ft);


        // Socket like APIs
    public:
        template <typename T1 = Application, typename T2 = Application> // T1: local Application, T2: remote Application
        std::enable_if_t<std::is_base_of_v<Application, T1> && std::is_base_of_v<Application, T2>, Connection &>
        connect(Tuple::FiveTuple fivetuple)
        {
            //TODO: if port = 0, then select a random free port

            auto cs5t = FiveTuple_to_ClientServerFiveTuple(fivetuple);

            auto *connection = connection_table.lookup(cs5t);
            if (connection != nullptr)
            {
                std::cout << "[!]\tCan't connection; connection already exists!" << std::endl;
                exit(1);
            }

            switch (fivetuple.protocol)
            {
                case IPPROTO_TCP:
                    return connect_tcp<T1, T2>(fivetuple);
                case IPPROTO_UDP:
                    return connect_udp<T1, T2>(fivetuple);
                default:
                    std::cout << "[!]\tInvalid protocol!" << std::endl;
                    exit(1);
            }
        };

        template <typename T1 = Application, typename T2 = Application> // T1: local Application, T2: remote Application
        std::enable_if_t<std::is_base_of_v<Application, T1> && std::is_base_of_v<Application, T2>, void>
        listen(Tuple::FiveTuple fivetuple)
        {
            if (fivetuple.source_ip != netdev.ip_address)
            {
                std::cout << "[!]\tcan't bind to address" << std::endl;
                exit(1);
            }

            switch (fivetuple.protocol)
            {
                case IPPROTO_TCP:
                    return listen_tcp<T1, T2>(fivetuple);
                case IPPROTO_UDP:
                    return listen_udp<T1, T2>(fivetuple);
                default:
                    std::cout << "[!]\tInvalid protocol!" << std::endl;
                    exit(1);
            }
        };

        void send(Connection &connection, std::vector<uint8_t> &data)
        {
            switch (connection.protocol())
            {
                case IPPROTO_TCP:
                    return send_tcp((TcpConnection &)connection, data);
                case IPPROTO_UDP:
                    return send_udp((UdpConnection &)connection, data);
                default:
                    std::cout << "[!]\tInvalid protocol!" << std::endl;
                    exit(1);
            }
        };

        void close(Connection &connection)
        {
            switch (connection.protocol())
            {
                case IPPROTO_TCP:
                    return close_tcp((TcpConnection &)connection);
                case IPPROTO_UDP:
                    return close_udp((UdpConnection &)connection);
                default:
                    std::cout << "[!]\tInvalid protocol!" << std::endl;
                    exit(1);
            }
        };


    private:
        template <typename T1 = Application, typename T2 = Application> // T1: client Application, T2: server Application
        std::enable_if_t<std::is_base_of_v<Application, T1> && std::is_base_of_v<Application, T2>, TcpConnection &>
        connect_tcp(Tuple::FiveTuple fivetuple)
        {
            auto cs5t = FiveTuple_to_ClientServerFiveTuple(fivetuple);
            auto *connection = new TcpConnection(cs5t);
            connection->set_client_application_type<T1>();
            connection->set_server_application_type<T2>();
            connection_table.add(connection);

            // SYN
            Tins::TCP syn_tcp(fivetuple.destination_port, fivetuple.source_port);
            syn_tcp.set_flag(Tins::TCP::SYN, 1);
            auto seq_number = (rand() % (65535 - 1024)) + 1024;
            syn_tcp.seq(seq_number);
            syn_tcp.ack_seq(0);
            Tins::Packet syn_packet = packetize(syn_tcp, fivetuple.destination_ip, fivetuple.source_ip);
            connection->update(syn_packet);
            output_packet(syn_packet, fivetuple.destination_ip);

            // Wait for SYNACK
            sleep(1); // TODO: block until connection is established

            return *connection;
        };

        template <typename T1 = Application, typename T2 = Application> // T1: client Application, T2: server Application
        std::enable_if_t<std::is_base_of_v<Application, T1> && std::is_base_of_v<Application, T2>, UdpConnection &>
        connect_udp(Tuple::FiveTuple fivetuple)
        {
            auto cs5t = FiveTuple_to_ClientServerFiveTuple(fivetuple);
            auto *connection = new UdpConnection(cs5t);
            connection->set_client_application_type<T1>();
            connection->set_server_application_type<T2>();
            connection_table.add(connection);
            return *connection;
        };

        template <typename T1 = Application, typename T2 = Application> // T1: local Application, T2: remote Application
        std::enable_if_t<std::is_base_of_v<Application, T1> && std::is_base_of_v<Application, T2>, void>
        listen_tcp(Tuple::FiveTuple fivetuple)
        {
            if(std::find(listening_tcp_ports.begin(), listening_tcp_ports.end(), fivetuple.source_port) != listening_tcp_ports.end())
            {
                std::cout << "[!]\tcan't bind to port" << std::endl;
                exit(1);
            }
            listening_tcp_ports.push_back(fivetuple.source_port);
        };

        template <typename T1 = Application, typename T2 = Application> // T1: local Application, T2: remote Application
        std::enable_if_t<std::is_base_of_v<Application, T1> && std::is_base_of_v<Application, T2>, void>
        listen_udp(Tuple::FiveTuple fivetuple)
        {
            if(std::find(listening_udp_ports.begin(), listening_udp_ports.end(), fivetuple.source_port) != listening_udp_ports.end())
            {
                std::cout << "[!]\tcan't bind to port" << std::endl;
                exit(1);
            }
            listening_udp_ports.push_back(fivetuple.source_port);
        };

        void send_tcp(TcpConnection &connection, std::vector<uint8_t> &data)
        {
            // TODO: segmentation to MSS sized segments

            bool is_server = netdev.ip_address == connection.server_ip();
            Tins::TCP data_tcp = Tins::TCP(is_server ? connection.client_port() : connection.server_port(),
                                is_server ? connection.server_port() : connection.client_port()) / Tins::RawPDU(data);
            data_tcp.set_flag(Tins::TCP::ACK, 1);
            data_tcp.seq(is_server ? connection.server_flow().SND_NXT : connection.client_flow().SND_NXT);
            data_tcp.ack_seq(is_server ? connection.server_flow().RCV_NXT : connection.client_flow().RCV_NXT);
            Tins::Packet data_packet = packetize(data_tcp, is_server ? connection.client_ip() : connection.server_ip(), is_server ? connection.server_ip() : connection.client_ip());
            connection.update(data_packet);
            output_packet(data_packet, is_server ? connection.client_ip() : connection.server_ip());
        };

        void send_udp(UdpConnection &connection, std::vector<uint8_t> &data)
        {
            bool is_server = netdev.ip_address == connection.server_ip();

            Tins::UDP data_udp = Tins::UDP(is_server ? connection.client_port() : connection.server_port(),
                                           is_server ? connection.server_port() : connection.client_port()) / Tins::RawPDU(data);
            Tins::Packet data_packet = packetize(data_udp, is_server ? connection.client_ip() : connection.server_ip(), is_server ? connection.server_ip() : connection.client_ip());
            connection.update(data_packet);
            output_packet(data_packet, is_server ? connection.client_ip() : connection.server_ip());
        };

        void close_tcp(TcpConnection &connection)
        {
            bool is_server = netdev.ip_address == connection.server_ip();

            // FIN
            Tins::TCP fin_tcp(  is_server ? connection.client_port() : connection.server_port(),
                                is_server ? connection.server_port() : connection.client_port());
            fin_tcp.set_flag(Tins::TCP::FIN, 1);
            fin_tcp.seq(is_server ? connection.server_flow().SND_NXT : connection.client_flow().SND_NXT);
            fin_tcp.ack_seq(is_server ? connection.server_flow().RCV_NXT : connection.client_flow().RCV_NXT);
            Tins::Packet fin_packet = packetize(fin_tcp, is_server ? connection.client_ip() : connection.server_ip(), is_server ? connection.server_ip() : connection.client_ip());
            connection.update(fin_packet);
            output_packet(fin_packet, is_server ? connection.client_ip() : connection.server_ip());

            // Should we be blocking until FIN + ACK is received ?
        };

        void close_udp(UdpConnection &connection)
        {
            ;
        };
};
