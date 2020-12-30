#include "PcapReplayNetworkStack/pcap_replay_network_stack.h"

bool compare_command(FTP::Request &message1, FTP::Request &message2)
{
    return message1.command() == message2.command();
}

bool compare_arguments(FTP::Request &message1, FTP::Request &message2)
{
    return message1.arguments() == message2.arguments();
}

bool compare_code(FTP::Reply &message1, FTP::Reply &message2)
{
    return message1.code() == message2.code();
}

bool compare_message(FTP::Reply &message1, FTP::Reply &message2)
{
    return message1.message() == message2.message();
}

bool compare_requests(bool predicate (FTP::Request &message1, FTP::Request &message2), std::vector<std::reference_wrapper<FTP::Request>> &messages1, std::vector<std::reference_wrapper<FTP::Request>> &messages2)
{
    //    assert(messages1.size() == messages2.size());
    for (int i=0; i < messages1.size(); i++)
    {
        if (!predicate(messages1[i].get(), messages2[i].get()))
            return false;
    }
    return true;
}

bool compare_replys(bool predicate (FTP::Reply &message1, FTP::Reply &message2), std::vector<std::reference_wrapper<FTP::Reply>> &messages1, std::vector<std::reference_wrapper<FTP::Reply>> &messages2)
{
    for (int i=0; i < std::min(messages1.size(), messages2.size()); i++)
    {
        if (!predicate(messages1[i].get(), messages2[i].get()))
            return false;
    }
    return true;
}

bool PcapReplayNetworkStack::received_expected_ftp(FtpApplication &original_application, FtpApplication &replayed_application)
{
    auto original_requests = original_application.requests();
    auto original_replys = original_application.replys();
    auto replayed_requests = replayed_application.requests();
    auto replayed_replys = replayed_application.replys();

    auto idk1 = original_requests.size();
    auto idk2 = original_replys.size();
    auto idk3 = replayed_requests.size();
    auto idk4 = replayed_requests.size();

    if (config.tx_event_ftp_request && original_requests.size() > replayed_requests.size())
    {
        return false;
    }
    if (config.tx_event_ftp_reply && original_replys.size() > replayed_replys.size())
    {
        return false;
    }

    if (config.tx_event_ftp_request)
    {
        if (config.tx_event_ftp_request_command)
        {
            if (!compare_requests(compare_command, original_requests, replayed_requests))
            {
                return false;
            }
        }
        if (config.tx_event_ftp_request_arguments)
        {
            if (!compare_requests(compare_arguments, original_requests, replayed_requests))
            {
                return false;
            }
        }
    }

    if (config.tx_event_ftp_reply)
    {
        if (config.tx_event_ftp_reply_code)
        {
            if (!compare_replys(compare_code, original_replys, replayed_replys))
            {
                return false;
            }
        }
        if (config.tx_event_ftp_reply_message)
        {
            if (!compare_replys(compare_message, original_replys, replayed_replys))
            {
                return false;
            }
        }
    }

    return true;
}
