#include "TCPIPNetworkStack/Transport/flow.h"
#include "tcp_reassembler.h"
#include "tins_tcp_reassembler.h"

#pragma once

// Transmission Control Block is implemented here

class TcpFlow final: public Flow
{
    public:
        explicit TcpFlow(Tuple::FiveTuple fiveTuple);

    public:
        void update(Tins::Packet &packet) final;
        [[nodiscard]] const std::vector<uint8_t> &local_payload() final;
        [[nodiscard]] const std::vector<uint8_t> &remote_payload() final;

    // TODO: clean this up from here below
    public:
        enum State
        {
            CLOSED1 = 0, // No connection / TCB yet
            LISTEN = 10,
            SYN_SENT = 20,
            SYN_RECEIVED = 30,
            ESTABLISHED = 100,
            FIN_WAIT_1 = 120,
            FIN_WAIT_2 = 121,
            CLOSE_WAIT = 110,
            CLOSING = 126,
            LAST_ACK = 111,
            TIME_WAIT = 130,
            CLOSED2 = 200 // Connection has closed
        };

        State state = CLOSED1;

        // sending side variables
        std::string local_ip = five_tuple().source_ip;
        uint16_t local_port = five_tuple().source_port;
        uint32_t ISS = 0; // initial send sequence number
        uint32_t SND_UNA = 0; // send unacknowledged
        uint32_t SND_NXT = 0; // send next
        bool local_timestamps = false;
        uint32_t local_tsval = 0;
        uint8_t local_rst_count = 0; // number of times we reset the connection

        // receiving side variables
        std::string remote_ip = five_tuple().destination_ip;
        uint16_t remote_port = five_tuple().destination_port;
        uint32_t IRS = 0; // initial receive sequence number
        uint32_t RCV_NXT = 0; // receive next
        bool remote_timestamps = false;
        uint32_t remote_tsval = 0;
        uint8_t remote_rst_count = 0; // number of times the remote host has reset the connection
        bool local_payload_complete(); // returns true when local_payload() is expected to no longer increase in size
        bool remote_payload_complete(); // returns true when remote_payload() is expected to no longer increase in size

    private:
        const std::vector<uint8_t> & payload(bool _is_server);
        bool is_server = false;
        bool is_client = false;
        TinsTcpReassembler reassembler;
};