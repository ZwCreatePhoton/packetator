#include "TCPIPNetworkStack/Internet/IPv6/IPv6Defragmenter.h"

IPv6Defragmenter::IPv6Defragmenter() = default;

void IPv6Defragmenter::ProcessPacket(Tins::Packet packet)
{
    _packet_count++;

    // TODO: reassembly

    _datagram_count++;
    if (callback != nullptr)
        callback(packet);
}
