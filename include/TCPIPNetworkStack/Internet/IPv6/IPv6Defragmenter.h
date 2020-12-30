#include <tins/tins.h>
#include "TCPIPNetworkStack/Internet/defragmenter.h"

#pragma once

class IPv6Defragmenter : public Defragmenter
{
    public:
        IPv6Defragmenter();

    public:
        void ProcessPacket(Tins::Packet packet) override;

};
