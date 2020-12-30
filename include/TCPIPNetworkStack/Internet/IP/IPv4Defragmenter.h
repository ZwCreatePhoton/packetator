#include <tins/tins.h>
#include "TCPIPNetworkStack/Internet/defragmenter.h"


#pragma once


class IPv4Defragmenter : public Defragmenter
{
    public:
        IPv4Defragmenter();

    public:
        void ProcessPacket(Tins::Packet packet) override;

    private:
        Tins::IPv4Reassembler reassembler{};
};
