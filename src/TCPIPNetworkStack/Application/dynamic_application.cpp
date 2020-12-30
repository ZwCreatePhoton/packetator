#include <iostream>
#include <TCPIPNetworkStack/Application/dns_application.h>

#include "TCPIPNetworkStack/Application/dynamic_application.h"

DynamicApplication::DynamicApplication(Application &application)
{
    assert(application.buffered_rx_segments.size() == application.buffered_rx_segments.size());
    _is_server = application.is_server();
    for (auto & buffered_rx_segment : application.buffered_rx_segments)
        DynamicApplication::update_rx(buffered_rx_segment);
    for (auto & buffered_tx_segment : application.buffered_tx_segments)
        DynamicApplication::update_tx(buffered_tx_segment);
}

void DynamicApplication::update_rx(std::vector <uint8_t> &segment)
{
    if (underlaying_application() != nullptr)
        underlaying_application()->update_rx(segment);
    Application::update_rx(segment);
}

void DynamicApplication::update_tx(std::vector <uint8_t> &segment)
{
    if (underlaying_application() != nullptr)
        underlaying_application()->update_tx(segment);
    Application::update_tx(segment);
}

Application::Protocol DynamicApplication::protocol()
{
    if (_protocol == Application::Protocol::UNKNOWN)
        update_protocol();
    return _protocol;
}

void DynamicApplication::update_protocol()
{
    std::vector<uint8_t> rx_data{};
    std::vector<uint8_t> tx_data{};
    for (auto segment : buffered_rx_segments)
        rx_data.insert(std::end(rx_data), std::begin(segment), std::end(segment));
    for (auto segment : buffered_tx_segments)
        tx_data.insert(std::end(tx_data), std::begin(segment), std::end(segment));

    // ApplicationClassifier::guess takes in the fully buffered client/server data as input
    _protocol = ApplicationClassifier::guess(rx_data, tx_data);
}

Application *DynamicApplication::underlaying_application()
{
    if (underlaying_app == nullptr)
    {
        switch (protocol())
        {
            case Application::Protocol::HTTP:
                underlaying_app = std::make_unique<HttpApplication>(*this);
                break;
            case Application::Protocol::DNS:
                underlaying_app = std::make_unique<DnsApplication>(*this);
                break;
            default:
                break;
        }
    }

    return underlaying_app.get();
}
