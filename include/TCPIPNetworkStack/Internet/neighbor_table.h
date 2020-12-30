#include <list>
#include <map>
#include <mutex>

#pragma once

#define NEIGHBOR_FREE        0
#define NEIGHBOR_WAITING     1
#define NEIGHBOR_RESOLVED    2


struct NeighborTableEntry
{
//    uint16_t hwtype;
    std::string sip;
    std::string smac;
    unsigned int state;
};

class NeighborTable
{
    public:
        void update(const std::string&, const std::string&);
        std::string lookup(const std::string&);
    private:
        std::mutex arp_mtx;
        std::list<NeighborTableEntry> arp_table;
};
