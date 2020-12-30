#include <iostream>
#include <algorithm>

#include "TCPIPNetworkStack/Transport/TCP/tcp_flow.h"
#include "utils.h"

using std::pair;

TcpFlow::TcpFlow(Tuple::FiveTuple fiveTuple) : Flow(std::move(fiveTuple)), reassembler(TinsTcpReassembler())
{}

void TcpFlow::update(Tins::Packet &packet)
{
    std::string sip;
    std::string dip;

    Tins::TCP *tcp;
    auto *ip4 = packet.pdu()->find_pdu<Tins::IP>();
    if(ip4 != nullptr)
    {
        sip = ip4->src_addr().to_string();
        dip = ip4->dst_addr().to_string();
        tcp = ip4->find_pdu<Tins::TCP>();
    }
    else
    {
        auto *ip6 = packet.pdu()->find_pdu<Tins::IPv6>();
        sip = ip6->src_addr().to_string();
        dip = ip6->dst_addr().to_string();
        tcp = ip6->find_pdu<Tins::TCP>();
    }

    auto sport = tcp->sport();
    auto dport = tcp->dport();

    if (    !(
            (sip == local_ip && dip == remote_ip && sport == local_port && dport == remote_port) ||
            (sip == remote_ip && dip == local_ip && sport == remote_port && dport == local_port) ))
    {
        std::cout << "[!]\tThis packet does not correspond to this TCP connection!" << std::endl;
        return;
    }

    // Track state
    // TX packet
    if (sip == local_ip)
    {
        if (tcp->flags() & Tins::TCP::SYN && !(tcp->flags() & Tins::TCP::ACK)) // SYN
        {
            switch (state)
            {
                case CLOSED1:
                case LISTEN:
                    state = SYN_SENT;
                    ISS = tcp->seq();
                    SND_UNA = ISS;
                    is_client = true;
                    break;
                default:
                    break;
            }
        }
        else if ((tcp->flags() & Tins::TCP::SYN) && (tcp->flags() & Tins::TCP::ACK)) // SYN + ACK
        {
            switch (state)
            {
                case SYN_RECEIVED:
                    ISS = tcp->seq();
                    SND_UNA = ISS;
                    break;
                case SYN_SENT:
                    state = ESTABLISHED;
                    break;
                default:
                    break;
            }
        }
        else if (!(tcp->flags() & Tins::TCP::SYN) && (tcp->flags() & Tins::TCP::ACK)) // ACK
        {
            ;
        }

        if (tcp->flags() & Tins::TCP::FIN)
        {
            switch (state)
            {
                case SYN_RECEIVED:
                case ESTABLISHED:
                    state = FIN_WAIT_1;
                    break;
                case CLOSE_WAIT:
                    state = LAST_ACK;
                    break;
                default:
                    break;
            }
        }

        if (tcp->flags() & Tins::TCP::RST)
        {
            local_rst_count++;
        }
        const Tins::TCP::option *ts_opt = tcp->search_option(Tins::TCP::TSOPT);
        local_timestamps |= ts_opt != nullptr;
        if (local_timestamps && ts_opt != nullptr) local_tsval = ts_opt->to<pair<uint32_t, uint32_t>>().first;
    }
        // RX packet
    else // sip == remote_sip
    {
        if (tcp->flags() & Tins::TCP::SYN && !(tcp->flags() & Tins::TCP::ACK))
        {
            switch (state)
            {
                case LISTEN:
                case SYN_SENT:
                    is_server = true;
                    state = SYN_RECEIVED;
                    IRS = tcp->seq();
                    break;
                default:
                    break;
            }
        }
        else if ((tcp->flags() & Tins::TCP::SYN) && (tcp->flags() & Tins::TCP::ACK))
        {
            switch (state)
            {
                case SYN_SENT:
                    state = ESTABLISHED;
                    IRS = tcp->seq();
                    break;
                default:
                    break;
            }
        }
        if (!(tcp->flags() & Tins::TCP::SYN) && tcp->flags() & Tins::TCP::ACK)
        {
            switch (state)
            {
                case SYN_RECEIVED:
                    state = ESTABLISHED;
                    break;
                default:
                    break;
            }
        }

        // FIN with no ACK
        if ((tcp->flags() & Tins::TCP::FIN) && !(tcp->flags() & Tins::TCP::ACK))
        {
            switch (state)
            {
                case FIN_WAIT_1:
                    state = CLOSING;
                    break;
                default:
                    break;
            }
        }
        // FIN + ACK
        else if ((tcp->flags() & Tins::TCP::FIN) && (tcp->flags() & Tins::TCP::ACK))
        {
            switch (state)
            {
                case FIN_WAIT_1:
                    state = TIME_WAIT;
                    break;
                default:
                    break;
            }
        }
        // ACK with no FIN
        else if (!(tcp->flags() & Tins::TCP::FIN) && (tcp->flags() & Tins::TCP::ACK))
        {
            switch (state)
            {
                case FIN_WAIT_1:
                    // Do i also need to check what the ACK number is?
                    state = FIN_WAIT_2;
                    break;
                default:
                    break;
            }
        }
        if (tcp->flags() & Tins::TCP::FIN)
        {
            switch (state)
            {
                case ESTABLISHED:
                    state = CLOSE_WAIT;
                    break;
                case FIN_WAIT_2:
                    state = TIME_WAIT;
                    break;
                default:
                    break;
            }
        }
        if (tcp->flags() & Tins::TCP::ACK)
        {
            switch (state)
            {
                case CLOSING:
                    state = TIME_WAIT;
                    break;
                case LAST_ACK:
                    state = CLOSED2;
                    break;
                default:
                    break;
            }
        }

        if (tcp->flags() & Tins::TCP::RST)
        {
            switch (state)
            {
                case SYN_RECEIVED:
                    state = LISTEN;
                    break;
                default:
                    break;
            }
            remote_rst_count++;
        }
        const Tins::TCP::option *ts_opt = tcp->search_option(Tins::TCP::TSOPT);
        remote_timestamps |= ts_opt != nullptr;
        if (remote_timestamps && ts_opt != nullptr) remote_tsval = ts_opt->to<pair<uint32_t, uint32_t>>().first;
    }

    // Reassemble data and track it
    reassembler.ProcessPacket(packet);

    // Update TCB variables

    // How likely is it that an initial sequence number is zero anyways?
    bool syn_recv = IRS != 0;
    bool syn_sent = ISS != 0;
    bool fin_recv = remote_payload_complete();
    bool fin_sent = local_payload_complete();

    if (syn_sent) SND_NXT = ISS + (int) syn_sent + local_payload().size() + (int) fin_sent;
    if (syn_recv) RCV_NXT = IRS + (int) syn_recv + remote_payload().size() + (int) fin_recv;

    if (syn_sent && syn_recv && // SND_UNA is initilized
        dip == local_ip && // RX
        tcp->flags() & Tins::TCP::ACK) //ACK
    {
        SND_UNA = std::max(SND_UNA, tcp->ack_seq());
    }
}


const std::vector<uint8_t> &TcpFlow::local_payload()
{
    if (!is_server && !is_client) return empty_vector; // No handshake observed yet
    if (is_server && is_client) // simultaneous open
    {
        std::cout << "[!] Simultaneous open not supported!" << std::endl;
        exit(1);
    }
    return payload(is_server);
}

const std::vector<uint8_t> &TcpFlow::remote_payload()
{
    if (!is_server && !is_client) return empty_vector; // No handshake observed yet
    if (is_server && is_client) // simultaneous open
    {
        std::cout << "[!] Simultaneous open not supported!" << std::endl;
        exit(1);
    }
    return payload(!is_server);
}

const std::vector<uint8_t> &TcpFlow::payload(bool _is_server)
{
    std::vector<Stream *> &streams = reassembler.Streams();
    if (streams.empty()) return empty_vector;
    return _is_server ? streams[0]->server_payload : streams[0]->client_payload;
}

bool TcpFlow::local_payload_complete()
{
    // we have already sent FIN
    return  state == FIN_WAIT_1 ||
            state == FIN_WAIT_2 ||
            state == CLOSING ||
            state == TIME_WAIT ||
            state == LAST_ACK ||
            state == CLOSED2;
}

bool TcpFlow::remote_payload_complete()
{
    // we have already received FIN
    return  state == CLOSING ||
            state == TIME_WAIT ||
            state == CLOSE_WAIT ||
            state == LAST_ACK ||
            state == CLOSED2;
}
