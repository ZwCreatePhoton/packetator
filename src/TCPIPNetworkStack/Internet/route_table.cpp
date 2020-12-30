#include <tins/ip.h>
#include <tins/ipv6_address.h>
#include <cassert>
#include "TCPIPNetworkStack/Internet/route_table.h"


void RouteTable::add(std::string dst, std::string gateway, std::string netmask, uint8_t flags, uint32_t metric)
{
    bool dst_is_ipv4 = (dst.find('.') != std::string::npos);
    bool gateway_is_ipv4 = (gateway.find('.') != std::string::npos);
    bool netmask_is_ipv4 = (netmask.find('.') != std::string::npos);

    assert(dst_is_ipv4 == netmask_is_ipv4);
    assert(gateway.empty() ? true : dst_is_ipv4 == gateway_is_ipv4 );

    std::lock_guard<std::mutex> lg(route_mtx);
    // Update entry if it exists
    for (auto& entry : route_table)
    {
        // Is this how you update a route table entry
        if(entry.dst == dst && entry.netmask == netmask)
        {
            entry.gateway = gateway;
            entry.flags = flags;
            entry.metric = metric;
            return;
        }
    }
    // Insert entry when it doesn't already exist
    RouteTableEntry entry{};
    entry.dst = dst;
    entry.gateway = gateway;
    entry.netmask = netmask;
    entry.flags = flags;
    entry.metric = metric;
    route_table.push_back(entry);
}

// TODO: incorporate metric
RouteTableEntry * RouteTable::lookup(const std::string& dst)
{
    std::lock_guard<std::mutex> lg(route_mtx);
    for (auto& entry : route_table)
    {
        bool dst_is_ipv4 = (dst.find('.') != std::string::npos);
        bool entry_dst_is_ipv4 = (entry.dst.find('.') != std::string::npos);

        if (!dst_is_ipv4 != !entry_dst_is_ipv4) // XOR
            continue;

        if (dst_is_ipv4)
        {
            auto dst_addr = Tins::IPv4Address(dst);
            auto entry_dst_addr = Tins::IPv4Address(entry.dst);
            auto entry_netmask_addr = Tins::IPv4Address(entry.netmask);
            if((dst_addr & entry_netmask_addr) == (entry_dst_addr & entry_netmask_addr))
            {
                return &entry;
            }
        }
        else
        {
            auto dst_addr = Tins::IPv6Address(dst);
            auto entry_dst_addr = Tins::IPv6Address(entry.dst);
            auto entry_netmask_addr = Tins::IPv6Address(entry.netmask);
            if((dst_addr & entry_netmask_addr) == (entry_dst_addr & entry_netmask_addr))
            {
                return &entry;
            }
        }
    }
    return nullptr;
}

void RouteTable::clear()
{
    std::lock_guard<std::mutex> lg(route_mtx);
    route_table.clear();
}
