#include "TCPIPNetworkStack/Transport/TCP/tcp_reassembler.h"

TcpReassembler::~TcpReassembler()
{
    for (auto stream : streams) delete stream;
}

void TcpReassembler::ProcessPackets(std::vector<Tins::Packet> &packets)
{
    for (auto& packet : packets) ProcessPacket(packet);
}

void TcpReassembler::ProcessPcap(std::string &pcap_filepath)
{
    Tins::FileSniffer sniffer(pcap_filepath);

    sniffer.sniff_loop([&](Tins::Packet& packet) {
        ProcessPacket(packet);
        return true;
    });
}

std::vector<Stream *> & TcpReassembler::Streams()
{
    return streams;
}
