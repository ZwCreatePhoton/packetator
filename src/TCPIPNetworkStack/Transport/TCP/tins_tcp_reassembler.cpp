#include <cassert>
#include "TCPIPNetworkStack/Transport/TCP/tins_tcp_reassembler.h"

TinsTcpReassembler::TinsTcpReassembler()
{
    // setup follower callbacks
    follower.new_stream_callback([&](Tins::TCPIP::Stream& stream) {
        new_stream_callback(stream);
    });
}

void TinsTcpReassembler::ProcessPacket(Tins::Packet packet)
{
    follower.process_packet(packet);
}

void TinsTcpReassembler::new_stream_callback(Tins::TCPIP::Stream &stream)
{
    stream.auto_cleanup_payloads(false);
    int stream_index = streams.size();
    auto *s = new Stream;
    s->client_address = stream.is_v6() ? stream.client_addr_v6().to_string() : stream.client_addr_v4().to_string();
    s->server_address = stream.is_v6() ? stream.server_addr_v6().to_string() : stream.server_addr_v4().to_string();
    s->client_port = stream.client_port();
    s->server_port = stream.server_port();
    streams.push_back(s);

    // setup callbacks to copy the reassembled data into vectors we control
    stream.client_data_callback([&, stream_index](Tins::TCPIP::Stream& stream) {
        client_data_callback(stream_index, stream);
    });
    stream.server_data_callback([&, stream_index](Tins::TCPIP::Stream& stream) {
        server_data_callback(stream_index, stream);
    });
}

void TinsTcpReassembler::client_data_callback(int stream_index, Tins::TCPIP::Stream &stream)
{
    const Tins::TCPIP::Stream::payload_type& payload = stream.client_payload();
    std::vector<uint8_t> &target_payload = streams[stream_index]->client_payload;

    auto size_diff = payload.size() - target_payload.size();
    target_payload.insert(target_payload.end(), payload.end() - size_diff, payload.end());


}

void TinsTcpReassembler::server_data_callback(int stream_index, Tins::TCPIP::Stream &stream)
{
    const Tins::TCPIP::Stream::payload_type& payload = stream.server_payload();
    std::vector<uint8_t> &target_payload = streams[stream_index]->server_payload;

    auto size_diff = payload.size() - target_payload.size();
    target_payload.insert(target_payload.end(), payload.end() - size_diff, payload.end());
}
