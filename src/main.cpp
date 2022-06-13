#include <iostream>
#include <unistd.h>
#include <random>
#include <ctime>

#include <yaml-cpp/yaml.h>
#include <tins/tins.h>
#include <tclap/CmdLine.h>


#include <PcapReplayNetworkStack/pcap_replay_network_stack_config.h>
#include <PcapReplayNetworkStack/pcap_replay_network_stack.h>
#include <utils.h>
#include "TCPIPNetworkStack/Link/networking.h"
#include "TCPIPNetworkStack/host.h"

/*
 * error codes:
 * 1    generic error codes ; need to make these more specific
 * 2    Message too long (MTU too small)
 * 3    No packets to replay
 */


struct Nic
{
    std::string name{};
    std::string first_ip{};
    std::string netmask{};
    std::string gateway{};
};

void parse_config(PcapReplayNetworkStackConfig &config, std::string config_path)
{
    YAML::Node yaml = YAML::LoadFile(config_path);

    if (yaml["take_packet_capture"]) config.take_packet_capture = yaml["take_packet_capture"].as<bool>();

    if (yaml["early_address_resolution_ping"]) config.early_address_resolution_ping = yaml["early_address_resolution_ping"].as<bool>();
    if (yaml["early_arp"]) config.early_arp = yaml["early_arp"].as<bool>();
    if (yaml["early_garp_request"]) config.early_garp_request = yaml["early_garp_request"].as<bool>();
    if (yaml["early_garp_reply"]) config.early_garp_reply = yaml["early_garp_reply"].as<bool>();
    if (yaml["early_unsolicited_na"]) config.early_unsolicited_na = yaml["early_unsolicited_na"].as<bool>();

    if (yaml["stop_on_unexpected_rst"]) config.stop_on_unexpected_rst = yaml["stop_on_unexpected_rst"].as<bool>();
    if (yaml["stop_on_unexpected_fin"]) config.stop_on_unexpected_fin = yaml["stop_on_unexpected_fin"].as<bool>();
    if (yaml["stop_on_timeout"]) config.stop_on_timeout = yaml["stop_on_timeout"].as<bool>();

    if (yaml["remove_time_outlier_seconds"]) config.remove_time_outlier_seconds = std::chrono::microseconds(yaml["remove_time_outlier_seconds"].as<long>());
    if (yaml["remove_time_outlier_packet"]) config.remove_time_outlier_packet = yaml["remove_time_outlier_packet"].as<bool>();

    if (yaml["honor_time_delta_min_microseconds"]) config.honor_time_delta_min_microseconds = std::chrono::microseconds(yaml["honor_time_delta_min_microseconds"].as<long>());
    if (yaml["honor_time_delta_previous_tx"]) config.honor_time_delta_previous_tx = yaml["honor_time_delta_previous_tx"].as<bool>();

    if (yaml["tx_event_internet"]) config.tx_event_internet = yaml["tx_event_internet"].as<bool>();
    if (yaml["tx_event_packet_count"]) config.tx_event_packet_count = yaml["tx_event_packet_count"].as<bool>();
    if (yaml["tx_event_datagram_count"]) config.tx_event_datagram_count = yaml["tx_event_datagram_count"].as<bool>();

    if (yaml["tx_event_transport"]) config.tx_event_transport = yaml["tx_event_transport"].as<bool>();
    if (yaml["tx_event_packet_count_if_no_transport"]) config.tx_event_packet_count_if_no_transport = yaml["tx_event_packet_count_if_no_transport"].as<bool>();
    if (yaml["tx_event_datagram_count_if_no_transport"]) config.tx_event_datagram_count_if_no_transport = yaml["tx_event_datagram_count_if_no_transport"].as<bool>();
    if (yaml["tx_event_udp_all_connections"]) config.tx_event_udp_all_connections = yaml["tx_event_udp_all_connections"].as<bool>();
    if (yaml["tx_event_udp_data"]) config.tx_event_udp_data = yaml["tx_event_udp_data"].as<bool>();
    if (yaml["tx_event_tcp_all_connections"]) config.tx_event_tcp_all_connections = yaml["tx_event_tcp_all_connections"].as<bool>();
    if (yaml["tx_event_tcp_segment_count"]) config.tx_event_tcp_segment_count = yaml["tx_event_tcp_segment_count"].as<bool>();
    if (yaml["tx_event_tcp_state"]) config.tx_event_tcp_state = yaml["tx_event_tcp_state"].as<bool>();
    if (yaml["tx_event_tcp_data"]) config.tx_event_tcp_data = yaml["tx_event_tcp_data"].as<bool>();

    if (yaml["tx_event_udp_application"]) config.tx_event_udp_application = yaml["tx_event_udp_application"].as<bool>();
    if (yaml["tx_event_tcp_application"]) config.tx_event_tcp_application = yaml["tx_event_tcp_application"].as<bool>();
    if (yaml["tx_event_http"]) config.tx_event_http = yaml["tx_event_http"].as<bool>();
    if (yaml["tx_event_http_state"]) config.tx_event_http_state = yaml["tx_event_http_state"].as<bool>();
    if (yaml["tx_event_http_state_header_count_nonzero"]) config.tx_event_http_state_header_count_nonzero = yaml["tx_event_http_state_header_count_nonzero"].as<bool>();
    if (yaml["tx_event_http_header_count_nonzero"]) config.tx_event_http_header_count_nonzero = yaml["tx_event_http_header_count_nonzero"].as<bool>();
    if (yaml["tx_event_http_header_count"]) config.tx_event_http_header_count = yaml["tx_event_http_header_count"].as<bool>();
    if (yaml["tx_event_http_raw_body"]) config.tx_event_http_raw_body = yaml["tx_event_http_raw_body"].as<bool>();
    if (yaml["tx_event_http_normalized_body"]) config.tx_event_http_normalized_body = yaml["tx_event_http_normalized_body"].as<bool>();
    if (yaml["tx_event_http_normalized_body_chunking"]) config.tx_event_http_normalized_body_chunking = yaml["tx_event_http_normalized_body_chunking"].as<bool>();
    if (yaml["tx_event_dns"]) config.tx_event_dns = yaml["tx_event_dns"].as<bool>();
    if (yaml["tx_event_dns_question_section"]) config.tx_event_dns_question_section = yaml["tx_event_dns_question_section"].as<bool>();
    if (yaml["tx_event_dns_response_section"]) config.tx_event_dns_response_section = yaml["tx_event_dns_response_section"].as<bool>();
    if (yaml["tx_event_dns_authority_section"]) config.tx_event_dns_authority_section = yaml["tx_event_dns_authority_section"].as<bool>();
    if (yaml["tx_event_dns_additional_section"]) config.tx_event_dns_additional_section = yaml["tx_event_dns_additional_section"].as<bool>();

    if (yaml["tx_event_ftp"]) config.tx_event_ftp = yaml["tx_event_ftp"].as<bool>();
    if (yaml["tx_event_ftp_request"]) config.tx_event_ftp_request = yaml["tx_event_ftp_request"].as<bool>();
    if (yaml["tx_event_ftp_request_command"]) config.tx_event_ftp_request_command = yaml["tx_event_ftp_request_command"].as<bool>();
    if (yaml["tx_event_ftp_request_arguments"]) config.tx_event_ftp_request_arguments = yaml["tx_event_ftp_request_arguments"].as<bool>();
    if (yaml["tx_event_ftp_reply"]) config.tx_event_ftp_reply = yaml["tx_event_ftp_reply"].as<bool>();
    if (yaml["tx_event_ftp_reply_code"]) config.tx_event_ftp_reply_code = yaml["tx_event_ftp_reply_code"].as<bool>();
    if (yaml["tx_event_ftp_reply_message"]) config.tx_event_ftp_reply_message = yaml["tx_event_ftp_reply_message"].as<bool>();

    if (yaml["modify_internet"]) config.modify_internet = yaml["modify_internet"].as<bool>();
    if (yaml["modify_transport"]) config.modify_transport = yaml["modify_transport"].as<bool>();
    if (yaml["modify_udp_sport_if_client"]) config.modify_udp_sport_if_client = yaml["modify_udp_sport_if_client"].as<bool>();
    if (yaml["modify_udp_dport_if_server"]) config.modify_udp_dport_if_server = yaml["modify_udp_dport_if_server"].as<bool>();
    if (yaml["modify_udp_dport_if_client"]) config.modify_udp_dport_if_client = yaml["modify_udp_dport_if_client"].as<bool>();
    if (yaml["modify_udp_sport_if_server"]) config.modify_udp_sport_if_server = yaml["modify_udp_sport_if_server"].as<bool>();
    if (yaml["modify_udp_data"]) config.modify_udp_data = yaml["modify_udp_data"].as<bool>();
    if (yaml["modify_udp_data_allow_shrinkage"]) config.modify_udp_data_allow_shrinkage = yaml["modify_udp_data_allow_shrinkage"].as<bool>();
    if (yaml["modify_udp_data_allow_growth"]) config.modify_udp_data_allow_growth = yaml["modify_udp_data_allow_growth"].as<bool>();
    if (yaml["modify_tcp_sport_if_client"]) config.modify_tcp_sport_if_client = yaml["modify_tcp_sport_if_client"].as<bool>();
    if (yaml["modify_tcp_dport_if_server"]) config.modify_tcp_dport_if_server = yaml["modify_tcp_dport_if_server"].as<bool>();
    if (yaml["modify_seq"]) config.modify_seq = yaml["modify_seq"].as<bool>();
    if (yaml["modify_ack_2"]) config.modify_ack_2 = yaml["modify_ack_2"].as<bool>();
    if (yaml["modify_tcp_timestamps"]) config.modify_tcp_timestamps = yaml["modify_tcp_timestamps"].as<bool>();
    if (yaml["modify_tcp_data"]) config.modify_tcp_data = yaml["modify_tcp_data"].as<bool>();
    if (yaml["modify_tcp_data_allow_shrinkage"]) config.modify_tcp_data_allow_shrinkage = yaml["modify_tcp_data_allow_shrinkage"].as<bool>();
    if (yaml["modify_tcp_data_allow_growth"]) config.modify_tcp_data_allow_growth = yaml["modify_tcp_data_allow_growth"].as<bool>();
    if (yaml["modify_application"]) config.modify_application = yaml["modify_application"].as<bool>();
    if (yaml["modify_ftp_reply_banner_ip"]) config.modify_ftp_reply_banner_ip = yaml["modify_ftp_reply_banner_ip"].as<bool>();
    if (yaml["modify_ftp_reply_passive_ip"]) config.modify_ftp_reply_passive_ip = yaml["modify_ftp_reply_passive_ip"].as<bool>();
    if (yaml["modify_ftp_request_passive_ip"]) config.modify_ftp_request_passive_ip = yaml["modify_ftp_request_passive_ip"].as<bool>();
    if (yaml["modify_dns_request_tid"]) config.modify_dns_request_tid = yaml["modify_dns_request_tid"].as<bool>();
    if (yaml["modify_dns_response_tid"]) config.modify_dns_response_tid = yaml["modify_dns_response_tid"].as<bool>();
}

void cmdline_run(int argc, char** argv)
{
    try
    {
        TCLAP::CmdLine cmd("Packet replay tool", ' ', "1.0");

        TCLAP::ValuesConstraint<std::string> allowed_ccmVals( {"FourTuple", "FiveTuple"} );
        TCLAP::ValueArg<std::string> connection_conversion_method("","ccm","Connection conversion method. Defaults to FiveTuple.", false, "FiveTuple", &allowed_ccmVals, cmd);
        TCLAP::MultiArg<std::string> ip_addresses("a","address",R"(IP address of the host to be simulated followed by a comma "," and name of the interface to use for this host followed by (optionally) a comma "," and the mac address to use for this host)",true,"x.x.x.x,eth0,00:11:22:33:44:55", cmd);
        TCLAP::MultiArg<std::string> ip_address_map("m","map-address","Map IP address from the pcap to the IP address of the host to be simulated (format: 'x.x.x.x=y.y.y.y')",true,"x.x.x.x=y.y.y.y", cmd);
        TCLAP::ValueArg<std::string> pcapPath("p","pcap","filepath to the pcap to replay",true,"some.pcap","path/file.pcap", cmd);
        TCLAP::ValueArg<int> timeout("t", "timeout","timeout in seconds", false, 10, "int", cmd);
        TCLAP::MultiArg<std::string> configs("c", "config", "configuration file", true, "config.yaml", cmd);
        TCLAP::ValueArg<std::string> blocklist("b", "blocklist", "yaml document with (mac) addresses to blocklist.", false, "", "yaml file", cmd);
        TCLAP::SwitchArg packet_capture("w","packet_capture","Take packet capture.", cmd, false);
        TCLAP::SwitchArg routed("r","routed","Set this if there is a layer 3 device inline. The gateway(s) addresses should be set appropriately.", cmd, false);
        TCLAP::MultiArg<std::string> gateways("g","gateway","The default gateway for the NIC",false,"x.x.x.x", cmd);
        TCLAP::MultiArg<std::string> subnets("s","subnet","the subnet of the network the NIC interface connects to",true,"x.x.x.x/n", cmd);
        TCLAP::MultiArg<std::string> interface_names("i","interface","NIC interface to send packets out of",true,"eth0", cmd);

        cmd.parse( argc, argv );

        std::string pcap_path = pcapPath.getValue();
        std::map<std::string, std::string> pcap_ip_map;
        std::vector<std::string> simulated_ips = ip_addresses.getValue();

        for (auto map_str : ip_address_map)
        {
            auto delim_index = std::find(map_str.begin(), map_str.end(), '=');
            if(delim_index==map_str.end())
            {
                std::cout << "Address mapping is missing delimiter '='" << std::endl << "\te.g. '1.2.3.4=5.6.7.8'" << std::endl;
                exit(1);
            }
            std::string old_ip(map_str.begin(), delim_index);
            std::string new_ip(delim_index+1, map_str.end());
            pcap_ip_map[old_ip] = new_ip;
        }

        if (interface_names.getValue().size() != subnets.getValue().size())
        {
            std::cout << "[!] number of interfaces and number of network masks must match"<< std::endl;
            exit(1);
        }

        if (routed.getValue() && (gateways.getValue().size()) != interface_names.getValue().size())
        {
            std::cout << "[!] number of gateways and number of interfaces must match when in routed mode"<< std::endl;
            exit(1);
        }

        std::vector<std::unique_ptr<Nic>> nics{};
        for (int i=0; i < interface_names.getValue().size(); i++)
        {
            std::string subnet = subnets.getValue()[i];
            std::string delim = "/";

            auto start = 0U;
            auto end = subnet.find(delim);
            while (end != std::string::npos)
            {
                start = end + delim.length();
                end = subnet.find(delim, start);
            }

            std::string prefix_length_str = subnet.substr(start, end);
            std::string first_ip = subnet.substr(0, start-1);
            uint32_t prefix_length = stoi(prefix_length_str);
            bool is_ipv4 = first_ip.find('.') != std::string::npos;
            std::string netmask = is_ipv4 ? Tins::IPv4Address::from_prefix_length(prefix_length).to_string() : Tins::IPv6Address::from_prefix_length(prefix_length).to_string();

            auto nic = std::make_unique<Nic>();
            nic->name = interface_names.getValue()[i];
            nic->first_ip = first_ip;
            nic->netmask = netmask;
            if (routed.getValue()) // assumes that config default for l3_device is false
                nic->gateway = gateways.getValue()[i];

            nics.push_back(move(nic));
        }

        // blocklists
        std::vector<std::string> mac_blocklist{};
        std::string blocklist_file = blocklist.getValue();
        if (!blocklist_file.empty())
        {
            YAML::Node yaml = YAML::LoadFile(blocklist_file);
            auto mac_bl = yaml["mac"];
            for (auto && i : mac_bl)
            {
                mac_blocklist.push_back(i.as<std::string>());
            }
        }

        // One-Time setup
        // For each interface...

        for (std::unique_ptr<Nic> &nic : nics)
        {
            // TODO: take care of this memory leak
            // Or not, its not that much memory anyway
            Tins::NetworkInterface *interface = new Tins::NetworkInterface(nic->name);
            Tins::PacketSender *sender = new Tins::PacketSender(*interface);
            sender->open_l2_socket(sender->default_interface());
            networking.AddTransmitter(sender);
        }

        PcapReplayNetworkStackConfig config(pcap_path, pcap_ip_map);
        for (const auto &config_path : configs.getValue())
            parse_config(config, config_path);
        config.l3_device = routed.getValue() ? true : config.l3_device;
        config.stop_on_timeout = timeout.getValue() != 0;
        config.timeout_duration = std::chrono::seconds(timeout.getValue());
        config.take_packet_capture = packet_capture.getValue() ? true : config.take_packet_capture;
        std::string ccm = connection_conversion_method.getValue();
        if (ccm == "FourTuple")
            config.connection_conversion_method = PcapReplayNetworkStackConfig::FourTuple;
        if (ccm == "FiveTuple")
            config.connection_conversion_method = PcapReplayNetworkStackConfig::FiveTuple;
        config.PostProcess();

        // Set up the simulated hosts / stacks

        std::vector<std::unique_ptr<PcapReplayNetworkStack>> netstacks{};

        for (const auto& ip : simulated_ips)
        {
            Nic *nic = nullptr;
            std::string delim = ",";

            std::string ip_addr = "";
            std::string interface_name = "";
            std::string hw_address = "";

            size_t n = std::count(ip.begin(), ip.end(), ',');

            switch(n)
            {
                case 1:
                {
                    auto start = 0U;
                    auto end = ip.find(delim);
                    while (end != std::string::npos)
                    {
                        start = end + delim.length();
                        end = ip.find(delim, start);
                    }
                    ip_addr = ip.substr(0, start-1);
                    interface_name = ip.substr(start, end);
                    break;
                }
                case 2:
                {
                    auto start = 0U;
                    auto end = ip.find(delim);
                    while (end != std::string::npos)
                    {
                        start = end + delim.length();
                        end = ip.find(delim, start);
                    }
                    std::string ip_addr_interface_name = ip.substr(0, start-1);
                    hw_address = ip.substr(start, end);
                    auto start2 = 0U;
                    auto end2 = ip_addr_interface_name.find(delim);
                    while (end2 != std::string::npos)
                    {
                        start2 = end2 + delim.length();
                        end2 = ip_addr_interface_name.find(delim, start2);
                    }
                    ip_addr = ip_addr_interface_name.substr(0, start2-1);
                    interface_name = ip_addr_interface_name.substr(start2, end2);
                    break;
                }
                default:
                    std::cout << "Invalid argument for -a" << std::endl;
                    exit(1);
            }

            for (auto &nic_ptr : nics)
            {
                if (nic_ptr->name == interface_name)
                {
                    nic = nic_ptr.get();
                    break;
                }
            }
            if (nic == nullptr)
            {
                std::cout << "missing the interface name?" << std::endl;
                exit(1);
            }

            bool is_ipv4 = nic->netmask.find('.') != std::string::npos;
            std::string mask = is_ipv4 ? nic->netmask : Tins::IPv6Address(nic->netmask).to_string(); // Normalize IPv6 address

            // todo: handle the following memory leaks (when cmdline_run exits) (Might possibly move the construction and destruction of this to Host)
            // interface
            // netdev

            std::vector<std::string> all_ipaddresses{};
            for (auto &ip_a : pcap_ip_map)
                all_ipaddresses.push_back(ip_a.second);

            auto *interface = new Tins::NetworkInterface(nic->name);
            auto mac_address = !hw_address.empty() ? hw_address : interface->hw_address().to_string();
            auto *netdev = new NetworkDevice(*interface, all_ipaddresses,  ip_addr, mask, mac_address, mac_blocklist);
            if (!nic->gateway.empty())
                netdev->gateway = nic->gateway;
            auto netstack = std::make_unique<PcapReplayNetworkStack>(*netdev, config);
            netstacks.push_back(move(netstack));
        }

        for (auto &netstack : netstacks)
        {
            netstack->init();
        }

        std::vector<std::unique_ptr<std::thread>> tx_threads{};
        std::cout << "[+]\tStarting tx_loops" << std::endl;
        for (auto &netstack : netstacks)
        {
            auto tx_thread = std::make_unique<std::thread>(&PcapReplayNetworkStack::tx_loop, netstack.get());
            tx_threads.push_back(move(tx_thread));
        }
        // Join tx_loops
        for (auto &tx_thread : tx_threads)
        {
            tx_thread->join();
        }
        std::cout << "[+]\ttx_loops ended" << std::endl;

        usleep(100*1000); // Do I need this sleep?

         // stop pcaps
        for (auto &netstack : netstacks)
        {
            netstack->stop_packet_capture();
        }

        // Get verdict
        bool verdict = true; // True == replay was successful
        for (auto &netstack : netstacks)
        {
            verdict &= netstack->result();
        }

        // Stats
        std::cout << "[+]\tStats:" << std::endl;
        for (auto &netstack : netstacks)
        {
            bool is_ipv4 = netstack->netdev.ip_address.find(".") != std::string::npos;
            auto &tx_defrag = is_ipv4 ? netstack->ipv4defragmenter_tx : netstack->ipv6defragmenter_tx;
            auto &rx_defrag = is_ipv4 ? netstack->ipv4defragmenter_rx : netstack->ipv6defragmenter_rx;

            std::cout << "[+]\t" << netstack->netdev.ip_address << ":" << std::endl;
            std::cout << "[+]\t\t" << "tx packet count: " << tx_defrag->packet_count() << std::endl;
            std::cout << "[+]\t\t" << "rx packet count: " << rx_defrag->packet_count() << std::endl;
        }

        std::cout << "[+]\t Packet replay was " << (verdict ? "successful" : "not successful") << "!" << std::endl;

    } catch (TCLAP::ArgException &e)  // catch any exceptions
    { std::cerr << "error: " << e.error() << " for arg " << e.argId() << std::endl; }
}

int main(int argc, char** argv)
{
    srand((time(NULL) & 0xFFFF) | (getpid() << 16)); // seed the PRNG
    cmdline_run(argc, argv);
    exit(0);
}
