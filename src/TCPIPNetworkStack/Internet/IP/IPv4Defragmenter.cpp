#include "TCPIPNetworkStack/Internet/IP/IPv4Defragmenter.h"

IPv4Defragmenter::IPv4Defragmenter() = default;

void IPv4Defragmenter::ProcessPacket(Tins::Packet packet)
{
    _packet_count++;
    // Try to reassemble the packet
    Tins::IPv4Reassembler::PacketStatus status = reassembler.process(*packet.pdu());
    switch (status)
    {
        case Tins::IPv4Reassembler::FRAGMENTED:
            break;
        case Tins::IPv4Reassembler::REASSEMBLED:
        case Tins::IPv4Reassembler::NOT_FRAGMENTED:
            _datagram_count++;
            if (callback != nullptr)
                callback(packet);
            break;
    }
}
