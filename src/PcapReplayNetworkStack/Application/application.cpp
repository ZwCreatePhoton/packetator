#include <TCPIPNetworkStack/Application/application_classifier.h>
#include "PcapReplayNetworkStack/pcap_replay_network_stack.h"
#include "utils.h"
#include "TCPIPNetworkStack/Application/ftp_application.h"

void PcapReplayNetworkStack::preprocess_pcap_packets_application()
{
    // Identify the underlaying Application
    std::vector<Connection *> *connections = complete_original_connection_table.all();
    for (auto connection : *connections)
    {
        std::vector<uint8_t> client_rx_data = buffered_data(connection->client_application().buffered_rx_segments);
        std::vector<uint8_t> client_tx_data = buffered_data(connection->client_application().buffered_tx_segments);
//        std::vector<uint8_t> server_rx_data = buffered_data(connection->server_application().buffered_rx_segments);
//        std::vector<uint8_t> server_tx_data = buffered_data(connection->server_application().buffered_tx_segments);
        Application::Protocol client_protocol = ApplicationClassifier::guess(client_rx_data, client_tx_data);
//        Application::Protocol server_protocol = ApplicationClassifier::guess(server_rx_data, server_tx_data);
//        assert(client_protocol == server_protocol);
        // might add the above assertion back in. Commented it out for performance. No effect if ApplicationClassifier::guess is symmetrical (assummed)
        if (connection->protocol() == IPPROTO_TCP)
        {
            switch (client_protocol)
            {
                case Application::UNKNOWN:
                    break;
                case Application::HTTP:
                    connection->set_client_application_type<HttpApplication>();
                    connection->set_server_application_type<HttpApplication>();
                    break;
                case Application::DNS:
//                    connection->set_client_application_type<DnsApplication>();
//                    connection->set_server_application_type<DnsApplication>();
                    break;
                case Application::FTP:
                    connection->set_client_application_type<FtpApplication>();
                    connection->set_server_application_type<FtpApplication>();
                    break;
            }
        }
        else if (connection->protocol() == IPPROTO_UDP)
        {
            switch (client_protocol)
            {
                case Application::UNKNOWN:
                    break;
                case Application::HTTP:
                    break;
                case Application::DNS:
                    connection->set_client_application_type<DnsApplication>();
                    connection->set_server_application_type<DnsApplication>();
                    break;
                case Application::FTP:
                    break;
            }
        }
    }
    delete connections;
}

void PcapReplayNetworkStack::refresh_rewrite_map_application(Connection *complete_original_connection)
{
    if (config.modify_application)
    {
        // assumes that client and server have the same Application protocol
        if (complete_original_connection->protocol() == IPPROTO_TCP)
        {
            switch (complete_original_connection->client_application().protocol())
            {
                case Application::UNKNOWN:
                    break;
                case Application::HTTP:
                    break;
                case Application::DNS:
                    break;
                case Application::FTP:
                    refresh_tcp_rewrite_map_ftp((TcpConnection *)complete_original_connection);
                    break;
            }
        }
        else if (complete_original_connection->protocol() == IPPROTO_UDP)
        {
            switch (complete_original_connection->client_application().protocol())
            {
                case Application::UNKNOWN:
                    break;
                case Application::HTTP:
                    break;
                case Application::DNS:
                    refresh_udp_rewrite_map_dns((UdpConnection *)complete_original_connection);
                    break;
                case Application::FTP:
                    break;
            }
        }
    }
}