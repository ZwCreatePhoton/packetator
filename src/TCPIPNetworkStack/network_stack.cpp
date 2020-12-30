#include <iostream>
#include <thread>
#include <utils.h>

#include "TCPIPNetworkStack/network_stack.h"

NetworkStack::NetworkStack(NetworkDevice& networkDevice) : netdev(networkDevice) {}

NetworkStack::~NetworkStack()
{
    frame_queue.close();
    rx_producer_thread->detach(); // Anyway to signal libtins to stop blocking so that we can join instead detach ?
    rx_consumer_thread->join();
}

void NetworkStack::handle_frame(Tins::Packet &packet)
{
    auto &frame = packet.pdu()->rfind_pdu<Tins::EthernetII>();
//    std::cout << "[+]\tWe received a frame!" << std::endl;
//    std::cout << "[+]\tDestination mac address: " << frame.dst_addr() << std::endl;
//    std::cout << "[+]\tSource mac address: " << frame.src_addr() << std::endl;
}

void NetworkStack::rx_producer_loop(NetworkDevice netdev)
{
    while (enable_rx_loop)
    {
        frame_queue.push(netdev.receive());
    }
}

void NetworkStack::rx_consumer_loop()
{
    while (enable_rx_loop)
    {
        try
        {
            Tins::Packet packet = frame_queue.pop();
            handle_frame(packet);
        }
        catch (int e)
        {
            break;
        }
    }
}

void NetworkStack::init()
{
    // init RX loop(s)
    if (enable_rx_loop)
    {
        auto netdev0 = netdev;
        rx_producer_thread = std::make_unique<std::thread>(&NetworkStack::rx_producer_loop, this, netdev0);
        rx_consumer_thread = std::make_unique<std::thread>(&NetworkStack::rx_consumer_loop, this);
    }
}

void NetworkStack::disable_rx_loop()
{
    enable_rx_loop = false;
}
