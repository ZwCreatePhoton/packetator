#include <iostream>
#include <TCPIPNetworkStack/Application/ftp_application.h>

#include "PcapReplayNetworkStack/pcap_replay_network_stack.h"
#include "TCPIPNetworkStack/Application/dynamic_application.h"
#include "utils.h"

bool PcapReplayNetworkStack::received_expected_application(Connection *original_connection, bool is_server)
{
    if (debug_output) std::cout << "[+]Validation: Application: is_server = " << is_server << std::endl;

    Connection *replayed_connection = convert_Connection(original_connection, true);
    if (replayed_connection == nullptr)
    {
        if (debug_output) std::cout << "[+]Validation: Application: Can't locate replayed_connection " << std::endl;
        return false;
    }

    Application *original_application = is_server ? &original_connection->server_application() : &original_connection->client_application();
    Application *replayed_application = is_server ? &replayed_connection->server_application() : &replayed_connection->client_application();

    if (original_application->protocol() == Application::Protocol::UNKNOWN || replayed_application->protocol() == Application::Protocol::UNKNOWN)
    {
        if (debug_output) std::cout << "[+]Validation: Application: unknown protocol(s) " << std::endl;
        return false;
    }

    if (original_application->protocol() != replayed_application->protocol())
    {
        if (debug_output) std::cout << "[+]Validation: Application: protocol mismatch" << std::endl;
        return false;
    }

    try
    {
        auto old_proto = original_application->protocol();
        auto p_original_application = dynamic_cast<DynamicApplication&>(*original_application).underlaying_application();
        assert(p_original_application != nullptr);
        original_application = p_original_application;
        assert(original_application->protocol() == old_proto);
    }
    catch(const std::bad_cast& e) {}
    try
    {
        auto old_proto = replayed_application->protocol();
        auto p_replayed_application = dynamic_cast<DynamicApplication&>(*replayed_application).underlaying_application();
        assert(p_replayed_application != nullptr);
        replayed_application = p_replayed_application;
        assert(replayed_application->protocol() == old_proto);
    }
    catch(const std::bad_cast& e) {}

    switch (original_application->protocol())
    {
        case Application::Protocol::HTTP:
        {
            if (!config.tx_event_http) return false;
            try
            {
                auto &original_http_application = dynamic_cast<HttpApplication&>(*original_application);
                auto &replayed_http_application = dynamic_cast<HttpApplication&>(*replayed_application);
                return received_expected_http(original_http_application, replayed_http_application);
            }
            catch(const std::bad_cast& e)
            {
                std::cout << "[!]\tCould not cast to HttpApplication! wtf?" << std::endl;
                exit(1);
            }
        }
        case Application::Protocol::DNS:
        {
            if (!config.tx_event_dns) return false;
            try
            {
                auto &original_dns_application = dynamic_cast<DnsApplication&>(*original_application);
                auto &replayed_dns_application = dynamic_cast<DnsApplication&>(*replayed_application);
                return received_expected_dns(original_dns_application, replayed_dns_application);
            }
            catch(const std::bad_cast& e)
            {
                std::cout << "[!]\tCould not cast to DnsApplication! wtf?" << std::endl;
                exit(1);
            }
        }
        case Application::Protocol::FTP:
        {
            if (!config.tx_event_ftp) return false;
            try
            {
                auto &original_ftp_application = dynamic_cast<FtpApplication&>(*original_application);
                auto &replayed_ftp_application = dynamic_cast<FtpApplication&>(*replayed_application);
                return received_expected_ftp(original_ftp_application, replayed_ftp_application);
            }
            catch(const std::bad_cast& e)
            {
                std::cout << "[!]\tCould not cast to FtpApplication! wtf?" << std::endl;
                exit(1);
            }
        }
        default:
            // Unsupported application protocol
            return false;
    }
}

bool PcapReplayNetworkStack::received_expected_application(Connection *original_connection)
{
    return received_expected_application(original_connection, true) && received_expected_application(original_connection, false);
}
