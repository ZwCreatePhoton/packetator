#include <chrono>

#include "TCPIPNetworkStack/Link/network_device.h"

#pragma once

using Clock = std::chrono::high_resolution_clock;
using TimePoint = std::chrono::time_point<Clock>;

class PcapReplayNetworkStackConfig
{
    public:
        enum ConnectionConversionMethod
        {
            FourTuple = 0,
            FiveTuple = 1
        };

        std::map <std::string, std::string> &pcap_ip_map; // maps old IP addresses (from the original pcap) to new IP addresses (from the simulation)
        std::map<std::pair<std::string, std::string>, std::pair<std::string, std::string>> pcap_macip_map; // maps old mac,IP address tuples (from the original pcap) to new mac,IP address tuples (from the simulation)
        std::vector <Tins::Packet> *packets = new std::vector <Tins::Packet>();

        PcapReplayNetworkStackConfig(const std::string &pcap_filepath, std::map<std::string, std::string> &pcap_ip_map);
        PcapReplayNetworkStackConfig(const std::string &pcap_filepath, std::map<std::string, std::string> &pcap_ip_map, std::map<std::pair<std::string, std::string>, std::pair<std::string, std::string>> pcap_macip_map);

        void PostProcess(); // run after all class variables have been initialized

        ConnectionConversionMethod connection_conversion_method = FourTuple;

        // IP stack settings
        bool wait_for_arp_response = true; // Waits for ARP response when performing address resolution when sending an IP packet

        bool same_side = false; // True if both NICs are on the same side of the device
        bool l3_device = false; // If true will add the correct routes so that external_gateway/16 can talk to internal_gateway/16

        // Address resolution
        // Settings that solve the following problem:
        //      DUT is a L3 device that drops packets that trigger address resolution.
        // Should only select 1 in most cases.
        bool early_address_resolution = true; // "parent option" / catch all for the rest below
        bool early_address_resolution_ping = false; // Send an IP packet (ICMP echo request) AND wait 1 second before replaying packets to get the client's address into a DUT's arp cache
        // Sufficient for live/simulated server + live/simulated client configurations but at the cost of extra IP packet(s) hitting the wire
        bool early_arp = false; // Sends ARP request to all destinations in pcap AND wait 1 second before replaying packets to get our address into the DUT's arp cache if routed traffic, other wise to fill our own cache.
                                // Not sufficient for live server + simulated client configuration.
        bool early_garp_request = true; // Sends a gratuitous ARP request and wait 1 second. Functionally similar to early_arp but this would be destination IP agnostic. This is probably the proper solution. Assumes that gateways, if present, will learn addresses from RARP.
        bool early_garp_reply = true; // Sends a gratuitous ARP reply and wait 1 second. early_garp_request and early_garp_reply go well together. They're the default
        bool early_unsolicited_na = true; // Sends an unsolicited Neighbor Advertisement and wait 1 second.


        bool take_packet_capture = false;

        bool stop_on_timeout = true; // If the timeout is reached (timeout_duration), then stop the replaying of packets for this host
        Clock::duration timeout_duration = std::chrono::seconds(10);

        Clock::duration remove_time_outlier_seconds = std::chrono::seconds(300);
        bool remove_time_outlier_packet = true; // dont replay outlier (time) packets

        Clock::duration honor_time_delta_min_microseconds = std::chrono::microseconds(100);
        bool honor_time_delta_previous_tx = true; // time since last transmitted packet.
        // There are other (more complex) ways to honor time delta values like time since last TCB update
        //  time since last transmitted packet is the easiest one to implement with the current architecture (iteration though the original packet list and sending TX packets in order, serially, without looking behind)


        // TX event settings

        bool tx_event_internet = true;
        bool tx_event_packet_count = false;
        bool tx_event_datagram_count = false;

        bool tx_event_transport = true;

        bool tx_event_packet_count_if_no_transport = true;
        bool tx_event_datagram_count_if_no_transport = false;

        // TODO: fix tx_event_udp_all_connections / tx_event_tcp_all_connections ?
        // TODO: add in some way to learn & identify dependent and independent connections
        bool tx_event_udp_all_connections = true; // like tx_event_tcp_all_connections , but for UDP
        bool tx_event_udp_data = true; // like tx_event_tcp_data , but for UDP
        bool tx_event_udp_application = true; // like tx_event_tcp_application , but for UDP

        bool tx_event_tcp_all_connections = true; // if false, then TCP connection are assumed to be independent. -> if true, all TCP connections will be used to determined if we can continue with TX
        bool tx_event_tcp_segment_count = false;
//        bool tx_event_tcp_segment_count = true; // TODO: ? segment count but only check for at least 1 (if at least 1 in original) instead of equating segments count
        bool tx_event_tcp_state = true; // If true, we will use TCP connection states to determine if we should transmit the next packet
        bool tx_event_tcp_data = true; // If true, we will use TCP stream data to determine if we should transmit the next packet
        //        bool tx_event_tcp_seq = false; // If true, we will use TCP sequence numbers to determine if we should transmit the next packet
        bool tx_event_tcp_application = true; // If true (tx_event_tcp_data should also be true since we'll need to fallback to that), we will apply application context, if available, on TCP data to determine if we should transmit the next packet

        bool tx_event_http = true; // if true (tx_event_tcp_application should also be true), we will apply HTTP application context, if available, on TCP data to determine if we should transmit the next packet
        bool tx_event_http_state = true; // if true (tx_event_http should also be true), we will use the state of the HTTP parser to determine if we should transmit the next packet
        bool tx_event_http_state_header_count_nonzero = true; // if true (tx_event_state should also be true), we will use the existence of non-zero number of fully parsed headers as an additional HTTP parsing state. Useful if HTTP server sends responses as: [Status-Line, headers, emptyline+body]
        bool tx_event_http_header_count_nonzero = false; // if true (tx_event_http should also be true), we will use the existence of non-zero number of fully parsed headers to determine if we should transmit the next packet
        bool tx_event_http_header_count = false; // if true (tx_event_http should also be true), we will use the number of headers fully parsed to determine if we should transmit the next packet
        bool tx_event_http_raw_body = false; // if true (tx_event_http should also be true), we will use the raw body of all requests/responses to determine if we should transmit the next packet
        bool tx_event_http_normalized_body = true; // if true (tx_event_http should also be true), we will use the normalized body of all requests/responses to determine if we should transmit the next packet
//        bool tx_event_http_normalized_body_crlf = true; // saw somewhere that some servers might append CRLF to the body (Content-Length value off by len(CRLF))
        bool tx_event_http_normalized_body_chunking = true;
//        bool tx_event_http_normalized_body_compression = true;
        bool tx_event_dns = true;
        bool tx_event_dns_question_section = true; // if true (tx_event_dns should also be true), we will use the Question section of DNS messages, if present, to determine if we should transmit the next packet
        bool tx_event_dns_response_section = true; // if true (tx_event_dns should also be true), we will use the Response section of DNS messages, if present, to determine if we should transmit the next packet
        bool tx_event_dns_authority_section = true; // if true (tx_event_dns should also be true), we will use the Authority section of DNS messages, if present, to determine if we should transmit the next packet
        bool tx_event_dns_additional_section = true; // if true (tx_event_dns should also be true), we will use the Additional section of DNS messages, if present, to determine if we should transmit the next packet
        bool tx_event_ftp = true;
        bool tx_event_ftp_request = true;
        bool tx_event_ftp_request_command = true;
        bool tx_event_ftp_request_arguments = false;
        bool tx_event_ftp_reply = true;
        bool tx_event_ftp_reply_code = true;
        bool tx_event_ftp_reply_message = false;


        bool modify_internet = true;

        bool modify_transport = true;

        // ICMP settings
        bool modify_icmp_id = true; // Modify ICMP echo Identifier
        bool modify_icmp_seq = true; // Modify IMCP echo sequence number

        // UDP settings
        bool modify_udp_sport_if_client = true;// Modify sport (if client). Sets sport to a randomly generate value. Required if server is a live host with 4 tuple already in its connection table.
        bool modify_udp_dport_if_server = true;// Modify dport (if server). Sets dport to the source port of the client. Required if client is a live host
        bool modify_udp_dport_if_client = true;// Modify dport (if client). Sets dport to the source port of the TFTP request to this host. Required to replay TFTP connections when modify_udp_sport_if_client is enabled.
        bool modify_udp_sport_if_server = true;// Modify sport (if server). Sets sport to the destination port of the TFTP request acknowledgment to this host. Required to replay TFTP connections when modify_udp_dport_if_server is enabled.
        bool modify_udp_data = true; // If true, UDP data will be modified based on a (datagram # , byte #) -> (byte) mapping that is populated with the help of Application layer context (or possibly user input)
        bool modify_udp_data_allow_shrinkage = true;
        bool modify_udp_data_allow_growth = true;

        // TCP settings
        bool modify_tcp_sport_if_client = true;// Modify sport (if client). Sets sport to a randomly generate value. Required if server is a live host with 4 tuple already in its connection table.
        bool modify_tcp_dport_if_server = true;// Modify dport (if server). Sets dport to the source port of the client. Required if client is a live host

        // TODO: implement disable_syn_handshake + live_syn_handshake   // The only motivation for this is symmetry
        // TODO: implement disable_fin_handshake + live_fin_handshake   // This will solve the early connection termination problem that arises when a DUT closes a connection while we are still waiting on data
        //                                                              // Only a nice to have since the verdict for when this happens will be BLOCKED (are there any edge cases?) -> who cares if one side doesn't response to the early connection close attempt
        // TODO: implement disable_pure_ack + live_ack_handling // this will solve the acknowledgement problem that arises when segment boundaries differ on the inside and outside of the dut. The problem is merely a replay impurity
        // TODO: implement
        //        bool modify_ack_1 = false; //  Modify ACK number variant. Correct ACK value by added the difference between the (live) remote hosts initial SEQ and the initial SEQ of the remote host from the pcap. Required for live othersides; required for replaying through a TCP proxy.
                                                // This is sufficient when DUTs do not perform (de/re)assemble of TCP segments
        bool modify_seq = false; // Correct sequence number after modifying data length
        bool modify_ack_2 = true; // Modify ACK number variant 2. Sets ACK to the proper value based on the the last (in sequence space) SEQ number received from the remote host. Required for live othersides; required for replaying through a TCP proxy.
        bool modify_tcp_timestamps = true;  // Edit TCP timestamps. Sets the timestamp to TSval of the most recent TSval received
                                            // required for live othersides with timestamps enabled; required for replaying through a TCP proxy that relies on timestamps)
                                            // required sometimes when either client or server is live and the other is simulated (depends on how far TS values are no longer close together)
                                            // since incoming segments into the live machine will get dropped due to PAWS

        bool modify_tcp_data = true; // If true, TCP data will be modified based on a (seq #) -> (byte) mapping that is populated with the help of Application layer context (or possibly user input)
        bool modify_tcp_data_allow_shrinkage = true;
        bool modify_tcp_data_allow_growth = true;

        bool modify_application = true;
        bool modify_ftp_reply_banner_ip = true;
        bool modify_ftp_reply_passive_ip = true;
        bool modify_ftp_reply_passive_port = true;
        bool modify_ftp_request_passive_ip = true;
        bool modify_ftp_request_passive_port = true;
        bool modify_dns_request_tid = false;
        bool modify_dns_response_tid = false;


        bool stop_on_unexpected_rst = true; // Stop transmitting packets (for a single host) if the host receives an unexpected TCP RST
        bool stop_on_unexpected_fin = true; // Stop transmitting packets (for a single host) if the host receives a FIN while still waiting on data from the remote host



        // Partially or fully unimplemented
//        bool modify_ip_checksums = true;
//        bool maintain_incorrect_ip_checksums = true;

//        bool modify_icmp_checksums = true;
//        bool maintain_incorrect_icmp_checksums = true;

//        bool modify_tcp_checksums = true;
//        bool maintain_incorrect_tcp_checksums = true;

//        bool modify_seq = false;
};