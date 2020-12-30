#include <iostream>

#include "TCPIPNetworkStack/Application/ftp_application.h"

FtpApplication::FtpApplication(Application &application)
{
    assert(application.buffered_rx_segments.size() == application.buffered_rx_segments.size());
    _is_server = application.is_server();
    for (auto & buffered_rx_segment : application.buffered_rx_segments)
        FtpApplication::update_rx(buffered_rx_segment);
    for (auto & buffered_tx_segment : application.buffered_tx_segments)
        FtpApplication::update_tx(buffered_tx_segment);
}


void FtpApplication::update_rx(std::vector<uint8_t> &segment)
{
    Application::update_rx(segment);
    if (is_server())
        request_parser.process_segment(segment);
    else
        reply_parser.process_segment(segment);
}

void FtpApplication::update_tx(std::vector<uint8_t> &segment)
{
    Application::update_tx(segment);
    if (is_server())
        reply_parser.process_segment(segment);
    else
        request_parser.process_segment(segment);
}

Application::Protocol FtpApplication::protocol()
{
    return Application::Protocol::FTP;
}

std::vector<std::reference_wrapper<FTP::Reply>> FtpApplication::replys()
{
    std::vector<std::reference_wrapper<FTP::Reply>> rms{};

    for (auto &rm : reply_parser.replys())
        rms.emplace_back(rm.get());

    return rms;
}

std::vector<std::reference_wrapper<FTP::Request>> FtpApplication::requests()
{
    std::vector<std::reference_wrapper<FTP::Request>> rms{};

    for (auto &rm : request_parser.requests())
        rms.emplace_back(rm.get());

    return rms;
}
