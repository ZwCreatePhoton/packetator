#include <iostream>

#include "PcapReplayNetworkStack/pcap_replay_network_stack.h"
#include "utils.h"

bool compare_header_count_nonzero(HTTP::Message &message1, HTTP::Message &message2)
{
    auto count1 = message1.headers().size();
    auto count2 = message2.headers().size();
    return (count1 == 0 && count2 == 0) || (count1 != 0 && count2 != 0);
}

bool compare_header_count(HTTP::Message &message1, HTTP::Message &message2)
{
    return message1.headers().size() == message2.headers().size();
}

bool compare_message_state(HTTP::Message &message1, HTTP::Message &message2)
{
    // Conditions that need to be meet:
    //      1. message2 (replayed) message is in a later (~further along in parsing) or equal state than message1 (original)
    return message1.state() <= message2.state();
}

bool compare_message_state_header_count_nonzero(HTTP::Message &message1, HTTP::Message &message2)
{
    if (message1.state() == HTTP::State::START_LINE_PARSED && message2.state() == HTTP::State::START_LINE_PARSED)
    {
        return compare_header_count_nonzero(message1, message2);
    }
    else
        return message1.state() <= message2.state();
}

bool compare_message_raw_body(HTTP::Message &message1, HTTP::Message &message2)
{
    // Conditions that need to be meet:
    //      1. message1 (original) body data is a "substring" (starting at index=0) of message2 (replayed) body data
    return message2.body().compare(0, message1.body().size(), message1.body()) == 0;
}

bool compare_message_normalized_body(HTTP::Message &message1, HTTP::Message &message2, bool chunking = true)
{
    // Conditions that need to be meet:
    //      1. message1 (original) normalized body data is a "substring" (starting at index=0) of message2 (replayed) normalized body data
    auto body1 = message1.normalized_body(chunking);
    auto body2 = message2.normalized_body(chunking);
    return body2.compare(0, body1.size(), body1) == 0;
}

bool compare_message_normalized_body(std::vector<std::reference_wrapper<HTTP::Message>> &messages1, std::vector<std::reference_wrapper<HTTP::Message>> &messages2, bool chunking = true)
{
    //    assert(messages1.size() == messages2.size());
    for (int i=0; i < messages1.size(); i++)
    {
        if (!compare_message_normalized_body(messages1[i].get(), messages2[i].get(), chunking))
            return false;
    }
    return true;
}

bool compare_messages(bool predicate (HTTP::Message &message1, HTTP::Message &message2), std::vector<std::reference_wrapper<HTTP::Message>> &messages1, std::vector<std::reference_wrapper<HTTP::Message>> &messages2)
{
    for (int i=0; i < std::min(messages1.size(), messages2.size()); i++)
    {
        if (!predicate(messages1[i].get(), messages2[i].get()))
            return false;
    }
    return true;
}

extern bool debug_output;

// TODO: Move out of PcapReplayNetworkStack and into it's own class. (Should do for TCP as well)
bool PcapReplayNetworkStack::received_expected_http(HttpApplication &original_application, HttpApplication &replayed_application)
{
    auto original_requests = original_application.requests();
    auto original_responses = original_application.responses();
    auto replayed_requests = replayed_application.requests();
    auto replayed_responses = replayed_application.responses();

    if (original_requests.size() > replayed_requests.size())
    {
        if (debug_output) std::cout << "[+]\tValidation: HTTP: requests size mismtach (original = " << original_requests.size() << ", replayed = " << replayed_requests.size() << ")" << std::endl;
        return false;
    }
    if (original_responses.size() > replayed_responses.size())
    {
        if (debug_output) std::cout << "[+]\tValidation: HTTP: responses size mismatch (original = " << original_responses.size() << ", replayed = " << replayed_responses.size() << ")" << std::endl;
        return false;
    }

    if (config.tx_event_http_state)
    {
        if (config.tx_event_http_state_header_count_nonzero)
        {
            if (!compare_messages(compare_message_state_header_count_nonzero, original_requests, replayed_requests))
            {
                if (debug_output) std::cout << "[+]\tValidation: HTTP: requests state mismatch" << std::endl;
                return false;
            }
            if(!compare_messages(compare_message_state_header_count_nonzero, original_responses, replayed_responses))
            {
                if (debug_output) std::cout << "[+]\tValidation: HTTP: responses state mismatch" << std::endl;
                return false;
            }
        }
        else
        {
            if (!compare_messages(compare_message_state, original_requests, replayed_requests))
            {
                if (debug_output) std::cout << "[+]\tValidation: HTTP: requests state mismatch" << std::endl;
                return false;
            }
            if(!compare_messages(compare_message_state, original_responses, replayed_responses))
            {
                if (debug_output) std::cout << "[+]\tValidation: HTTP: responses state mismatch" << std::endl;
                return false;
            }
        }
    }

    if (config.tx_event_http_header_count_nonzero)
        if (    !compare_messages(compare_header_count_nonzero, original_requests, replayed_requests) ||
                !compare_messages(compare_header_count_nonzero, original_responses, replayed_responses))
            return false;

    if (config.tx_event_http_header_count)
        if (    !compare_messages(compare_header_count, original_requests, replayed_requests) ||
                !compare_messages(compare_header_count, original_responses, replayed_responses))
            return false;

    if (config.tx_event_http_raw_body)
    {
        if (!compare_messages(compare_message_raw_body, original_requests, replayed_requests))
        {
            if (debug_output) std::cout << "[+]\tValidation: HTTP: requests raw body mismatch" << std::endl;
            return false;
        }
        if(!compare_messages(compare_message_raw_body, original_responses, replayed_responses))
        {
            if (debug_output) std::cout << "[+]\tValidation: HTTP: responses raw body mismatch" << std::endl;
            return false;
        }
    }

    if (config.tx_event_http_normalized_body)
    {
        // Does it make since to compare normalized bodies when states != BODY_PARSED ?
        // What about when compression transfer-encodings are supported?
        bool chunking = config.tx_event_http_normalized_body_chunking;
        if (!compare_message_normalized_body(original_requests, replayed_requests, chunking))
        {
            if (debug_output) std::cout << "[+]\tValidation: HTTP: requests normalized body mismatch" << std::endl;
            return false;
        }
        if (!compare_message_normalized_body(original_responses, replayed_responses, chunking))
        {
            if (debug_output) std::cout << "[+]\tValidation: HTTP: responses normalized body mismatch" << std::endl;
            return false;
        }
    }

    return true;
}

