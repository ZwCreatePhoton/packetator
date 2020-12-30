#include <iostream>

#include "PcapReplayNetworkStack/pcap_replay_network_stack.h"
#include "utils.h"

bool equals(const Tins::DNS::query& q1, const Tins::DNS::query& q2)
{
    return  (q1.dname() == q2.dname()) &&
            (q1.query_type() == q2.query_type()) &&
            (q1.query_class() == q2.query_class());
}

bool equals(const Tins::DNS::resource& q1, const Tins::DNS::resource& q2)
{
    return  (q1.dname() == q2.dname()) &&
            (q1.data() == q2.data()) &&
            (q1.query_type() == q2.query_type()) &&
            (q1.query_class() == q2.query_class()) &&
            (q1.ttl() == q2.ttl());
}

bool compare_message_question_section(Tins::DNS &message1, Tins::DNS &message2)
{
    // TODO: Support reordering ?

    // Conditions that need to be meet:
    bool section1_parsing_error = false;
    try
    {
        message1.queries();
    }
    catch (Tins::malformed_packet &e)
    {
        section1_parsing_error = true;
    }
    bool section2_parsing_error = false;
    try
    {
        message2.queries();
    }
    catch (Tins::malformed_packet &e)
    {
        section2_parsing_error = true;
    }
    if (section2_parsing_error && section1_parsing_error)
    {
        return true;
    }
    else
    {
        if (section1_parsing_error ^ section2_parsing_error)
            return false;
    }
    if (message1.queries().size() != message2.queries().size())
        return false;
    for (int i=0; i < message1.queries().size();i++)
    {
        if (!equals(message1.queries()[i], message2.queries()[i]))
            return false;
    }

    return true;
}

bool compare_message_response_section(Tins::DNS &message1, Tins::DNS &message2)
{
    // TODO: Support reordering ?

    // Conditions that need to be meet:
    bool section1_parsing_error = false;
    try
    {
        message1.answers();
    }
    catch (Tins::malformed_packet &e)
    {
        section1_parsing_error = true;
    }
    bool section2_parsing_error = false;
    try
    {
        message2.answers();
    }
    catch (Tins::malformed_packet &e)
    {
        section2_parsing_error = true;
    }
    if (section2_parsing_error && section1_parsing_error)
    {
        return true;
    }
    else
    {
        if (section1_parsing_error ^ section2_parsing_error)
            return false;
    }
    if (message1.answers().size() != message2.answers().size())
        return false;
    for (int i=0; i < message1.answers().size();i++)
    {
        if (!equals(message1.answers()[i], message2.answers()[i]))
            return false;
    }

    return true;
}

bool compare_message_authority_section(Tins::DNS &message1, Tins::DNS &message2)
{
    // TODO: Support reordering ?

    // Conditions that need to be meet:
    bool section1_parsing_error = false;
    try
    {
        message1.authority();
    }
    catch (Tins::malformed_packet &e)
    {
        section1_parsing_error = true;
    }
    bool section2_parsing_error = false;
    try
    {
        message2.authority();
    }
    catch (Tins::malformed_packet &e)
    {
        section2_parsing_error = true;
    }
    if (section2_parsing_error && section1_parsing_error)
    {
        return true;
    }
    else
    {
        if (section1_parsing_error ^ section2_parsing_error)
            return false;
    }
    if (message1.authority().size() != message2.authority().size())
        return false;
    for (int i=0; i < message1.authority().size();i++)
    {
        if (!equals(message1.authority()[i], message2.authority()[i]))
            return false;
    }

    return true;
}

bool compare_message_additional_section(Tins::DNS &message1, Tins::DNS &message2)
{
    // TODO: Support reordering ?

    // Conditions that need to be meet:

    bool section1_parsing_error = false;
    try
    {
        message1.additional();
    }
    catch (Tins::malformed_packet &e)
    {
        section1_parsing_error = true;
    }
    bool section2_parsing_error = false;
    try
    {
        message2.additional();
    }
    catch (Tins::malformed_packet &e)
    {
        section2_parsing_error = true;
    }
    if (section2_parsing_error && section1_parsing_error)
    {
        return true;
    }
    else
    {
        if (section1_parsing_error ^ section2_parsing_error)
            return false;
    }

    if (message1.additional().size() != message2.additional().size())
        return false;
    for (int i=0; i < message1.additional().size();i++)
    {
        if (!equals(message1.additional()[i], message2.additional()[i]))
            return false;
    }

    return true;
}

bool compare_messages(bool predicate (Tins::DNS &message1, Tins::DNS &message2), std::vector<Tins::DNS> &messages1, std::vector<Tins::DNS> &messages2)
{
    for (int i=0; i < std::min(messages1.size(), messages2.size()); i++)
    {
        if (!predicate(messages1[i], messages2[i]))
            return false;
    }
    return true;
}

// TODO: Move out of PcapReplayNetworkStack and into it's own class. (Should do for TCP as well)
bool PcapReplayNetworkStack::received_expected_dns(DnsApplication &original_application, DnsApplication &replayed_application)
{
    auto original_requests = original_application.requests();
    auto original_responses = original_application.responses();
    auto replayed_requests = replayed_application.requests();
    auto replayed_responses = replayed_application.responses();

    if (original_requests.size() > replayed_requests.size())
    {
        if (debug_output)
            std::cout << "[+]\tValidation: DNS: requests size mismtach (original = " << original_requests.size()
                      << ", replayed = " << replayed_requests.size() << ")" << std::endl;
        return false;
    }
    if (original_responses.size() > replayed_responses.size())
    {
        if (debug_output)
            std::cout << "[+]\tValidation: DNS: responses size mismatch (original = " << original_responses.size()
                      << ", replayed = " << replayed_responses.size() << ")" << std::endl;
        return false;
    }

    if (config.tx_event_dns_question_section)
    {
        if (!compare_messages(compare_message_question_section, original_requests, replayed_requests))
        {
            if (debug_output) std::cout << "[+]\tValidation: DNS: requests Question section mismatch" << std::endl;
            return false;
        }
        if(!compare_messages(compare_message_question_section, original_responses, replayed_responses))
        {
            if (debug_output) std::cout << "[+]\tValidation: DNS: responses Question section mismatch" << std::endl;
            return false;
        }
    }

    if (config.tx_event_dns_response_section)
    {
        if (!compare_messages(compare_message_response_section, original_requests, replayed_requests))
        {
            if (debug_output) std::cout << "[+]\tValidation: DNS: requests Response section mismatch" << std::endl;
            return false;
        }
        if(!compare_messages(compare_message_response_section, original_responses, replayed_responses))
        {
            if (debug_output) std::cout << "[+]\tValidation: DNS: responses Response section mismatch" << std::endl;
            return false;
        }
    }

    if (config.tx_event_dns_authority_section)
    {
        if (!compare_messages(compare_message_authority_section, original_requests, replayed_requests))
        {
            if (debug_output) std::cout << "[+]\tValidation: DNS: requests Authority section mismatch" << std::endl;
            return false;
        }
        if(!compare_messages(compare_message_authority_section, original_responses, replayed_responses))
        {
            if (debug_output) std::cout << "[+]\tValidation: DNS: responses Authority section mismatch" << std::endl;
            return false;
        }
    }

    if (config.tx_event_dns_additional_section)
    {
        if (!compare_messages(compare_message_additional_section, original_requests, replayed_requests))
        {
            if (debug_output) std::cout << "[+]\tValidation: DNS: requests Additional section mismatch" << std::endl;
            return false;
        }
        if(!compare_messages(compare_message_additional_section, original_responses, replayed_responses))
        {
            if (debug_output) std::cout << "[+]\tValidation: DNS: responses Additional section mismatch" << std::endl;
            return false;
        }
    }

    return true;
}