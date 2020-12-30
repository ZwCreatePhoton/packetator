#include <string>
#include "TCPIPNetworkStack/Application/application.h"

Application::Application(bool is_server) : _is_server(is_server)
{}

Application::Application(Application &application)
{
    assert(application.buffered_rx_segments.size() == application.buffered_rx_segments.size());
    _is_server = application.is_server();
    for (auto & buffered_rx_segment : application.buffered_rx_segments)
        Application::update_rx(buffered_rx_segment);
    for (auto & buffered_tx_segment : application.buffered_tx_segments)
        Application::update_tx(buffered_tx_segment);
}

void Application::update_rx(std::vector <uint8_t> &segment)
{
    buffered_rx_segments.push_back(segment);
}

void Application::update_tx(std::vector <uint8_t> &segment)
{
    buffered_tx_segments.push_back(segment);
}

Application::Protocol Application::protocol()
{
    return UNKNOWN;
}

bool Application::is_server()
{
    return _is_server;
}
