#include "TCPIPNetworkStack/host.h"

Host::Host(NetworkStack &networkStack) : netstack(networkStack)
{
    init();
}

void Host::init()
{
    netstack.init();
}
