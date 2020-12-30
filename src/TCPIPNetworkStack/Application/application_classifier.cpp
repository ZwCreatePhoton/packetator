#include <iostream>

#include <tins/tins.h>

#include "TCPIPNetworkStack/Application/application_classifier.h"

uint8_t HTTP_HEADER_MIN_SIZE = 12; // this is an approximation

uint8_t DNS_HEADER_SIZE = 12;
uint8_t MIN_DNS_QUESTION_SIZE = 6;
uint8_t MIN_DNS_MESSAGE_SIZE = DNS_HEADER_SIZE + MIN_DNS_QUESTION_SIZE;
uint16_t TYPICAL_MAX_UDP_DNS_MESSAGE_SIZE = 512;

Application::Protocol ApplicationClassifier::guess(const std::vector<uint8_t> &rx_data, const std::vector<uint8_t> &tx_data)
{
    // convert payloads to string
    std::string rx_data_str = std::string(rx_data.begin(), rx_data.end());
    std::string tx_data_str = std::string(tx_data.begin(), tx_data.end());

    if (    rx_data.size() > HTTP_HEADER_MIN_SIZE &&
            tx_data.size() > HTTP_HEADER_MIN_SIZE &&
            (   std::memcmp(rx_data.data(), HTTP_RESPONSE_BYTES.data(), HTTP_RESPONSE_BYTES.size()) == 0 ||
                std::memcmp(tx_data.data(), HTTP_RESPONSE_BYTES.data(), HTTP_RESPONSE_BYTES.size()) == 0)
            )
//            std::regex_search(rx_data_str, HTTP_RESPONSE_REGEX) ||
//            std::regex_search(tx_data_str, HTTP_RESPONSE_REGEX) ||
//            std::regex_search(rx_data_str, HTTP_REQUEST_REGEX) ||
//            std::regex_search(tx_data_str, HTTP_REQUEST_REGEX)
//            )
    {
        return Application::Protocol::HTTP;
    }

    //https://stackoverflow.com/questions/7565300/identifying-dns-packets
    if (rx_data.size() > MIN_DNS_MESSAGE_SIZE && tx_data.size() > MIN_DNS_MESSAGE_SIZE && rx_data.size() < TYPICAL_MAX_UDP_DNS_MESSAGE_SIZE && tx_data.size() < TYPICAL_MAX_UDP_DNS_MESSAGE_SIZE)
    {
        std::unique_ptr<Tins::DNS> dns_rx;
        std::unique_ptr<Tins::DNS> dns_tx;
        try
        {
            dns_rx = std::make_unique<Tins::DNS>(rx_data.data(), rx_data.size());
        }
        catch (Tins::malformed_packet&) {}
        try
        {
            dns_tx = std::make_unique<Tins::DNS>(tx_data.data(), tx_data.size());
        }
        catch (Tins::malformed_packet&) {}

        if (dns_rx != nullptr && dns_tx != nullptr)
        {
            bool is_dns = true;

            // Assumes that Question count is always 1 for DNS messages
            is_dns &= dns_rx->questions_count() == 1 && dns_tx->questions_count() == 1;
            // Assumes that the RX stream and TX stream must contain different message types (query vs response)
            is_dns &= dns_rx->type() != dns_tx->type();

            if (is_dns)
            {
                Tins::DNS &query = dns_rx->type() == Tins::DNS::QUERY ? *dns_rx : *dns_tx;
                Tins::DNS &response = dns_rx->type() == Tins::DNS::RESPONSE ? *dns_rx : *dns_tx;

                // Assumes that queries contain no answers
                is_dns &= query.answers_count() == 0;
                // Assumes that queries contain no authoritys
                is_dns &= query.authority_count() == 0;
                // Assumes that queries rcode will be zero
                is_dns &= query.rcode() == 0;

                // typical response values
            }

            if (is_dns)
                return Application::Protocol::DNS;
        }
    }

    // SMTP placeholder
    if (
            (std::regex_search(rx_data_str, SMTP_BANNER_REGEX) && std::regex_search(tx_data_str, SMTP_HELO_REGEX)) ||
            (std::regex_search(tx_data_str, SMTP_BANNER_REGEX) && std::regex_search(rx_data_str, SMTP_HELO_REGEX)) )
    {
        return Application::Protocol::UNKNOWN;
    }

    if (
            (std::regex_search(rx_data_str, FTP_BANNER_REGEX) && std::regex_search(tx_data_str, FTP_COMMAND_REGEX)) ||
            (std::regex_search(tx_data_str, FTP_BANNER_REGEX) && std::regex_search(rx_data_str, FTP_COMMAND_REGEX)) )
    {
        return Application::Protocol::FTP;
    }


    return Application::Protocol::UNKNOWN;
}
