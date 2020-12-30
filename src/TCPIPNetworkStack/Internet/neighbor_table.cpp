#include "TCPIPNetworkStack/Internet/neighbor_table.h"


void NeighborTable::update(const std::string& ip_address, const std::string& mac_address)
{
    std::lock_guard<std::mutex> lg(arp_mtx);
    // Update entry if it exists
    for (auto& entry : arp_table)
    {
        if(entry.sip == ip_address)
        {
            entry.smac = mac_address;
            return;
        }
    }
    // Insert entry when it doesn't already exist
    NeighborTableEntry entry;
    entry.state = NEIGHBOR_RESOLVED;
    entry.sip = ip_address;
    entry.smac = mac_address;
    arp_table.push_back(entry);
}

std::string NeighborTable::lookup(const std::string& ip_address)
{
    std::lock_guard<std::mutex> lg(arp_mtx);
    for (const auto& entry : arp_table)
    {
        if(entry.state == NEIGHBOR_RESOLVED && entry.sip == ip_address)
        {
            return entry.smac;
        }
    }
    return "";
}
