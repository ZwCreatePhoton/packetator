#include <iostream>

#include "TCPIPNetworkStack/Application/dns_application.h"

DnsApplication::DnsApplication(Application &application)
{
    assert(application.buffered_rx_segments.size() == application.buffered_rx_segments.size());
    _is_server = application.is_server();
    for (auto & buffered_rx_segment : application.buffered_rx_segments)
        DnsApplication::update_rx(buffered_rx_segment);
    for (auto & buffered_tx_segment : application.buffered_tx_segments)
        DnsApplication::update_tx(buffered_tx_segment);
}

void DnsApplication::update_rx(std::vector<uint8_t> &segment)
{
    Application::update_rx(segment);
    try
    {
        // We assume that 1 segment = exactly 1 DNS query
        // TODO: Support segmentation (1 segment != exactly 1 DNS query)
        Tins::DNS dns = Tins::DNS(segment.data(), segment.size());
        rx_messages.push_back(dns);
    }
    catch (Tins::malformed_packet&) {}
}

void DnsApplication::update_tx(std::vector<uint8_t> &segment)
{
    Application::update_tx(segment);
    try
    {
        // We assume that 1 segment = exactly 1 DNS query
        // TODO: Support segmentation (1 segment != exactly 1 DNS query)
        Tins::DNS dns = Tins::DNS(segment.data(), segment.size());
        tx_messages.push_back(dns);
    }
    catch (Tins::malformed_packet&) {}}

Application::Protocol DnsApplication::protocol()
{
    return Application::Protocol::DNS;
}

std::vector<Tins::DNS> DnsApplication::responses()
{
    std::vector<Tins::DNS> rms{};

    for (auto &rm : rx_messages)
        if(rm.type() == Tins::DNS::RESPONSE)
            rms.emplace_back(rm);
    for (auto &rm : tx_messages)
        if(rm.type() == Tins::DNS::RESPONSE)
            rms.emplace_back(rm);

    return rms;
}

std::vector<Tins::DNS> DnsApplication::requests()
{
    std::vector<Tins::DNS> rms{};

    for (auto &rm : rx_messages)
        if(rm.type() == Tins::DNS::QUERY)
            rms.emplace_back(rm);
    for (auto &rm : tx_messages)
        if(rm.type() == Tins::DNS::QUERY)
            rms.emplace_back(rm);

    return rms;
}
