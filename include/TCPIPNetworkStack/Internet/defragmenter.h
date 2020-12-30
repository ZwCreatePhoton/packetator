#include <functional>

#include <tins/tins.h>

#pragma once


class Defragmenter
{
    protected:
        Defragmenter();

    public:
        virtual void ProcessPacket(Tins::Packet packet) = 0;
        virtual void ProcessPackets(std::vector<Tins::Packet> &packets);
        void SetCallback(std::function<void(Tins::Packet)> cb);
        [[nodiscard]] bool isCallbackSet();
        [[nodiscard]] uint64_t packet_count();
        [[nodiscard]] uint64_t datagram_count();

    protected:
        std::function<void(Tins::Packet)> callback = nullptr;
        uint64_t _packet_count = 0;
        uint64_t _datagram_count = 0;
};