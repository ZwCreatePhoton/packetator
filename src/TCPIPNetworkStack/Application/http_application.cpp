#include <iostream>

#include "TCPIPNetworkStack/Application/http_application.h"

HttpApplication::HttpApplication(Application &application)
{
    _is_server = application.is_server();
    rx_parser = HTTP::MessageParser(_is_server ? HTTP::MessageParser::Request :  HTTP::MessageParser::Response);
    tx_parser = HTTP::MessageParser(_is_server ? HTTP::MessageParser::Response :  HTTP::MessageParser::Request);
    for (auto & buffered_rx_segment : application.buffered_rx_segments)
        HttpApplication::update_rx(buffered_rx_segment);
    for (auto & buffered_tx_segment : application.buffered_tx_segments)
        HttpApplication::update_tx(buffered_tx_segment);
}

void print_messages(const std::vector<std::reference_wrapper<HTTP::Message>>& messages)
{
    for (auto &rm : messages)
    {
        auto &message = rm.get();
        std::cout << "[++++++]\t" << (message.is_request() ? "request" : "response") << std::endl;
        // headers
        for (auto &rh : message.headers())
        {
            auto &h = rh.get();
            std::cout << "[++++++]\t" << h.name() << " : "  << h.value() << std::endl;
        }
        std::cout << "body length = " << message.body().size() << std::endl;
    }
}

void HttpApplication::update_rx(std::vector<uint8_t> &segment)
{
    Application::update_rx(segment);
    rx_parser.process_segment(segment);
//    if (segment.empty()) print_messages(responses()); // debug
}

void HttpApplication::update_tx(std::vector<uint8_t> &segment)
{
    Application::update_tx(segment);
    tx_parser.process_segment(segment);
//    if (segment.empty()) print_messages(requests()); // debug
}

Application::Protocol HttpApplication::protocol()
{
    return Application::Protocol::HTTP;
}

std::vector<std::reference_wrapper<HTTP::Message>> HttpApplication::responses()
{
    std::vector<std::reference_wrapper<HTTP::Message>> rms{};

    for (auto &rm : rx_parser.messages())
        if(rm.get().is_response())
            rms.emplace_back(rm.get());
    for (auto &rm : tx_parser.messages())
        if(rm.get().is_response())
            rms.emplace_back(rm.get());

    return rms;
}

std::vector<std::reference_wrapper<HTTP::Message>> HttpApplication::requests()
{
    std::vector<std::reference_wrapper<HTTP::Message>> rms{};

    for (auto &rm : rx_parser.messages())
        if(rm.get().is_request())
            rms.emplace_back(rm.get());
    for (auto &rm : tx_parser.messages())
        if(rm.get().is_request())
            rms.emplace_back(rm.get());

    return rms;
}
