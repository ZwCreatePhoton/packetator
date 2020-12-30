#include <string>
#include <thread>

#include "TCPIPNetworkStack/network_stack.h"

#include "PcapReplayNetworkStack/pcap_replay_network_stack_config.h"

#pragma once

class Host
{
    public:
        NetworkStack &netstack;
        explicit Host(NetworkStack&);

    private:
        void init();
};
