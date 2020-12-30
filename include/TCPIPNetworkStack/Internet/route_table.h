#include <map>
#include <mutex>
#include <list>

#pragma once

#define RT_LOOPBACK 0x01
#define RT_GATEWAY  0x02
#define RT_HOST     0x04
#define RT_REJECT   0x08
#define RT_UP       0x10

struct RouteTableEntry
{
    std::string dst;
    std::string gateway;
    std::string netmask;
    uint8_t flags;
    uint32_t metric;
//    std::string iface;
};




class RouteTable
{
    public:
        void add(std::string dst, std::string gateway, std::string netmask, uint8_t, uint32_t);
        RouteTableEntry * lookup(const std::string& dst);
        void clear();
    private:
        std::mutex route_mtx;
        std::list<RouteTableEntry> route_table;
};
