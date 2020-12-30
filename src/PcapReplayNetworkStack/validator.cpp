#include <tins/tins.h>
#include <iostream>

#include "PcapReplayNetworkStack/validator.h"
#include "TCPIPNetworkStack/Transport/TCP/tins_tcp_reassembler.h"

Validator::Validator(std::map<std::string, std::string> &pcap_ip_map, const std::string& original_pcap, std::initializer_list<std::string> replayed_pcaps) : pcap_ip_map(pcap_ip_map)
{
    this->original_pcap = original_pcap;
    for (auto& replayed_pcap : replayed_pcaps)
    {
        this->replayed_pcaps.push_back(replayed_pcap);
    }
}

bool Validator::GetVerdict()
{
    bool verdict = true;

    // Setup reassemblers;
    TcpReassembler *original_reassembler = new TinsTcpReassembler();
    std::vector<TcpReassembler *> replayed_reassemblers{};
    for (auto& replayed_pcap : replayed_pcaps)
    {
        auto reassembler = new TinsTcpReassembler();
        replayed_reassemblers.push_back((TcpReassembler *)reassembler);
    }

    // Reassemble TCP streams
    original_reassembler->ProcessPcap(original_pcap);
    for (int i=0; i < replayed_pcaps.size(); i++)
        replayed_reassemblers[i]->ProcessPcap(replayed_pcaps[i]);

    // Get Stream objects
    std::vector<Stream *> original_streams = original_reassembler->Streams();
    std::vector<std::vector<Stream *>> replayed_streams_vector{};
    for (auto& reassembler : replayed_reassemblers)
        replayed_streams_vector.push_back(reassembler->Streams());

    // Compare streams
    for (const auto& replayed_streams : replayed_streams_vector) // Loop through all (replayed) pcaps
    {
        for (auto stream : replayed_streams) // Loop through all the streams in a pcap
        {
            bool found_otherside = false; // will be true if there exists a stream that is "equal" in a pcap different from this pcap
            for (const auto& r_s : replayed_streams_vector) // // Loop through all (replayed) pcaps besides this one
            {
                if (r_s == replayed_streams) continue;
                for (auto stream2 : r_s)
                {
                    if (equal_streams(*stream, *stream2)) found_otherside = true;
                }
            }
            if (!found_otherside) verdict = false; // If we fail to find an "equal" stream, then the replay was not successful (verdict is false)
        }
    }

    // cleanup
    delete original_reassembler;
    for (auto reassembler : replayed_reassemblers)
        delete reassembler;

    return verdict;
}

bool Validator::equal_streams(const Stream& stream1, const Stream& stream2)
{
    bool result =
            stream1.client_address == stream2.client_address && // Can we rely on the DUT NOT performing NAT ?
            stream1.server_address == stream2.server_address &&
            stream1.client_port == stream2.client_port && // Can we rely on the DUT NOT changing the client's source port on side the server is on?
            stream1.server_port == stream2.server_port &&
            stream1.client_payload == stream2.client_payload &&
            stream1.server_payload == stream2.server_payload;
    return result;
}
