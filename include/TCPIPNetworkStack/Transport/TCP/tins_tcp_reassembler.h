#include "tcp_reassembler.h"

#pragma once

// Uses the library Tins for TCP reassembly (IP fragment reassembly also happens behind the scenes. (Needs confirmation))

// Note:
/* The first 16 bytes of stream.client_payload() or .server_payload() gets
 * allocated with random bytes after processing a segment with FIN flag.
 * This is a bug that prevents use the client/server payloads from the
 * stream object. So we are just going to maintain our own copy of the payload
 * that'll get copied (by value) each time client_data_callback or server_data_callback
 * is called.
 *
 * Edit:
 * Looks like the stream objects are allocated on the stack
 * https://github.com/mfontanini/libtins/blob/22b4435c8115eb58e2c7372531a39b99f4a39f1e/src/tcp_ip/stream_follower.cpp#L89
 * Pretty surprising that the reassembly works...
 * So we probably shouldn't relay Tins::TCPIP::Stream pointers to last long ?
 *
 * TODO: see if the case where data is sent after sending a FIN is handled
*/

class TinsTcpReassembler : public TcpReassembler
{
    public:
        explicit TinsTcpReassembler();
        void ProcessPacket(Tins::Packet packet) override;

    private:
        Tins::TCPIP::StreamFollower follower{};
        void new_stream_callback(Tins::TCPIP::Stream&);
        void client_data_callback(int, Tins::TCPIP::Stream&);
        void server_data_callback(int, Tins::TCPIP::Stream&);
};
