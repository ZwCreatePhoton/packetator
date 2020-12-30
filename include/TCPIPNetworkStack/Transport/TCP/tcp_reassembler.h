#include <tins/tins.h>
#include <tins/tcp_ip/stream_follower.h>

#include "stream.h"

#pragma once


class TcpReassembler
{
    public:
        virtual ~TcpReassembler();
        virtual void ProcessPacket(Tins::Packet packet) = 0;
        virtual void ProcessPackets(std::vector<Tins::Packet> &packets);
        virtual void ProcessPcap(std::string &);
        std::vector<Stream *> & Streams();

    protected:
        std::vector<Stream *> streams{};
};