#include <queue>
#include <TCPIPNetworkStack/Application/dns_application.h>
#include <TCPIPNetworkStack/Application/ftp_application.h>

#include "TCPIPNetworkStack/Transport/connection_table.h"
#include "TCPIPNetworkStack/Transport/TCP/tcp_connection.h"
#include "TCPIPNetworkStack/tcp_ip_network_stack.h"
#include "pcap_replay_network_stack_config.h"
#include "TCPIPNetworkStack/Application/http_application.h"
#include "TCPIPNetworkStack/Internet/IP/IPv4Defragmenter.h"

class PcapReplayNetworkStack : public TCPIPNetworkStack
{
    public:
        std::map<std::string, std::string> &pcap_ip_map; // maps old IP addresses (from the original pcap) to new IP addresses (from the simulation)
        std::vector<Tins::Packet> packets{};
        PcapReplayNetworkStackConfig &config;

        PcapReplayNetworkStack(NetworkDevice &, PcapReplayNetworkStackConfig &);

        void handle_frame(Tins::Packet &packet) override;
        void handle_ipv4(Tins::Packet &packet) override;
        void handle_ipv4_nonfragment(Tins::Packet &packet) override;
        void handle_ipv6(Tins::Packet &packet) override;
        void handle_ipv6_nonfragment(Tins::Packet &packet) override;
        void handle_udp(Tins::Packet &packet) override;
        void handle_tcp(Tins::Packet &packet) override;
        void handle_tcp_connection_attempt(Tins::Packet &packet, TcpConnection &connection) override;
        void handle_tcp_data_ack(Tins::Packet &packet, TcpConnection &connection) override;
        void handle_tcp_connection_termination(Tins::Packet &packet, TcpConnection &connection) override;
        void tx_loop();
        void init() override;
        [[nodiscard]] bool result();
        bool enable_tx_loop = true;

        // pcap
        // TODO: Move out of the network stack? Maybe to Host?
        void start_packet_capture(); // Starts packet capture; non-blocking
        void stop_packet_capture();
        bool is_packet_capture_running();

    private:
        Tins::Packet pcap_start_packet; // the first packet in the pcap

        void preprocess_pcap_packets(std::vector <Tins::Packet> *);
        void preprocess_pcap_packets_ip();
        void preprocess_pcap_packets_ipv4();
        void preprocess_pcap_packets_ipv6();
        void preprocess_pcap_packets_transport(std::vector<Tins::Packet> &_packets);
        void preprocess_pcap_packets_udp(std::vector<Tins::Packet> &_packets);
        void preprocess_pcap_packets_tcp(std::vector<Tins::Packet> &_packets);
        void preprocess_pcap_packets_application();
        void process_next_original_packet(Tins::Packet &packet); // called once per packet in the original pcap as traffic is being replayed
        void process_next_original_packet_ip_possible_fragments(Tins::Packet &packet);
        void process_next_original_packet_ip(Tins::Packet &packet); // called ...
        void process_next_original_packet_ipv4(Tins::Packet &packet); // called ...
        void process_next_original_packet_ipv6(Tins::Packet &packet); // called ...
        void process_next_original_packet_transport(Tins::Packet packet); // called ...
        void process_next_original_packet_udp(Tins::Packet packet); // called ...
        void process_next_original_packet_tcp(Tins::Packet packet); // called ...

        void rewrite_packet(Tins::Packet &packet);
        void rewrite_packet_ip(Tins::Packet &packet);
        void rewrite_packet_ipv4(Tins::Packet &packet);
        void rewrite_packet_ipv6(Tins::Packet &packet);
        void rewrite_packet_udp(Tins::Packet &packet);
        void rewrite_packet_tcp(Tins::Packet &packet);
        bool exit_tx_loop_early();
        bool exit_tx_loop_early_tcp();
        bool received_expected();
        bool received_expected_ip();
        bool received_expected_ipv4();
        bool received_expected_ipv6();
        bool received_expected_transport();
        bool received_expected_udp();
        bool received_expected_tcp();
        void handle_rx_queue();
        void handle_rx_packet(Tins::Packet);

        // packet capture
        std::thread *packet_capture_thread{}; // thread for the packet capture;
        Tins::Sniffer *packet_capture_sniffer{};
        Tins::PacketWriter *packet_capture_writer{};
        bool packet_capture_in_progress = false;
        void packet_capture_loop();

        std::chrono::time_point<std::chrono::system_clock> tx_time = std::chrono::system_clock::time_point::min(); //time_point representing the last time we transmitted a packet
        std::chrono::time_point<std::chrono::system_clock> rx_time = std::chrono::system_clock::time_point::min(); //time_point representing the last time we received a packet

        // Application
        bool received_expected_application(Connection *original_connection);
        bool received_expected_application(Connection *original_connection, bool is_server);
        bool received_expected_http(HttpApplication &original_application, HttpApplication &replayed_application);
        bool received_expected_dns(DnsApplication &original_application, DnsApplication &replayed_application);
        bool received_expected_ftp(FtpApplication &original_application, FtpApplication &replayed_application);

        // Transport
        ConnectionTable complete_original_connection_table{};
        ConnectionTable original_connection_table{};
        bool received_expected_transport_data(Connection *original_connection);
        bool received_expected_transport_data(Connection *original_connection, bool is_server);
        void update_output(Tins::Packet &packet); // guaranteed to be a full IP/IP6 datagram
        void update_output_transport(Tins::Packet &packet); // guaranteed to be a full IP/IP6 datagram

        // UDP
        bool received_expected_udp_connection(UdpConnection *original_connection);
        std::map<UdpConnection *, std::map<std::tuple<uint32_t, uint16_t, uint16_t>, std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>> udp_rewrite_maps{}; // (complete original Connection*) -> ( (datagram #, byte #, length) -> (vector of old bytes with size = length, vector of new byte) )
        std::vector<std::pair<std::string, uint16_t>> remote_listening_udp_ports{}; // pair(remote_host , remote_port)
        std::vector<uint16_t> listening_udp_client_ports{}; // TFTP (and others?) protocols: client:1234 -> server:69 ; server:54321 -> client:1234 // here port 1234 would be in this vector
        std::vector<std::pair<std::string, uint16_t>> remote_listening_udp_client_ports{}; // pair(remote_host , remote_port)
        void refresh_udp_rewrite_map_dns(UdpConnection *complete_original_connection);

        // TCP
        std::vector<std::pair<std::string, uint16_t>> remote_listening_tcp_ports{}; // pair(remote_host , remote_port)
        bool received_expected_tcp_connection(TcpConnection *original_connection);
        bool any_unexpected_resets();
        bool any_unexpected_fins();
        std::map<TcpConnection *, std::map<std::tuple<uint32_t, uint32_t>, std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>> tcp_rewrite_maps{}; // (complete original Connection*) -> ( (relative sequence #, length) -> (vector of old bytes with size = length, vector of new byte) )
        void refresh_tcp_rewrite_map_ftp(TcpConnection *complete_original_connection);

        void refresh_rewrite_map_application(Connection *complete_original_connection);

        std::vector<int> expected{}; //PDU * = IP *
        std::vector<Tins::Packet> actual{}; // PDU * = IP *
        std::mutex rx_queue_mutex;
        std::queue<Tins::Packet> rx_queue;
        std::vector<Tins::Packet> received_packets;

        std::unique_ptr<Defragmenter> original_ipv4defragmenter_tx = std::make_unique<IPv4Defragmenter>();
        std::unique_ptr<Defragmenter> original_ipv4defragmenter_rx = std::make_unique<IPv4Defragmenter>();
        std::unique_ptr<Defragmenter> original_ipv4defragmenter_other = std::make_unique<IPv4Defragmenter>();
        std::unique_ptr<Defragmenter> original_ipv6defragmenter_tx = std::make_unique<IPv6Defragmenter>();
        std::unique_ptr<Defragmenter> original_ipv6defragmenter_rx = std::make_unique<IPv6Defragmenter>();
        std::unique_ptr<Defragmenter> original_ipv6defragmenter_other = std::make_unique<IPv6Defragmenter>();


        // ARP
        std::set<std::string> dips{};
        static Tins::IP early_arp_packet(std::string sip, std::string dip);
        static bool is_early_arp_packet_response(Tins::Packet &packet);
        const int early_arp_wait_time = 100*1000; // microseconds
        void perform_early_address_resolution();
        void perform_early_arp();
        void perform_early_garp_request();
        void perform_early_garp_reply();
        void perform_early_unsolicited_na();
        void init_route_table();


        void filter_pcap_packets(std::vector <Tins::Packet> *);
        void verify_pcap_packets(std::vector <Tins::Packet> *);
        void verify_pcap_ip_map();
        void populate_dips();

        int packets_index = 0;

        // IP utils
        static std::pair<std::string, std::string> get_source_dest_addresses(Tins::Packet &packet);
        bool is_tx_packet(const Tins::Packet& packet, bool original);
        bool is_tx_packet(int);
        bool is_rx_packet(const Tins::Packet& packet, bool original);
        bool is_rx_packet(int);
        std::string convert_ip_address(const std::string& ip, bool original);

        // Tuple utils
        Tuple::ClientServerFiveTuple FiveTuple_to_ClientServerFiveTuple(const Tuple::FiveTuple& ft, bool original);
        Tuple::ClientServerFourTuple convert_ClientServerFourTuple(Tuple::ClientServerFourTuple cs4t, bool original);

        // Transport utils
        bool is_source_server(const Tuple::FiveTuple& ft) override;
        bool is_source_server(const Tuple::FiveTuple& ft, bool original);

        std::unordered_map<Connection *, bool> received_expected_cache{}; // original connection * -> result
        std::unordered_map<Connection *, Connection *> convert_connection_cache{};
        std::unordered_map<Connection *, Connection *> convert_connection_to_complete_cache{};
        Connection * convert_Connection(Connection *connection, bool original);
        Connection * convert_Connection_to_complete_original(Connection *connection, bool original);
        Connection *convert_connection_to_request_connection(Connection *connection, ConnectionTable &ct);
        void set_application_types(Connection *connection, bool original);
};
