#include "TCPIPNetworkStack/tcp_ip_network_stack.h"

void TCPIPNetworkStack::output_frame(Tins::Packet &packet)
{
    auto &frame = packet.pdu()->rfind_pdu<Tins::EthernetII>();
    std::unique_ptr<Tins::PDU> frame_copy = std::unique_ptr<Tins::PDU>(frame.clone());
    netdev.transmit(*frame_copy);
}
