#include <thread>

#include <TCPIPNetworkStack/Link/network_device.h>
#include "SynchronizedQueue.h"

#pragma once


#ifdef UNIT_TESTING
#define VIRTUAL virtual
#else
#define VIRTUAL
#endif

class NetworkStack
{
    public:
        NetworkDevice &netdev;

        explicit NetworkStack(NetworkDevice &networkDevice);
        ~NetworkStack();

#ifdef UNIT_TESTING
        virtual ~NetworkStack() {};
#endif
        // might spawn new thread(s)
        virtual void init();
        void disable_rx_loop();

        // eth
        virtual void handle_frame(Tins::Packet &packet);

    private:
        std::unique_ptr<std::thread> rx_producer_thread;
        std::unique_ptr<std::thread> rx_consumer_thread;
        void rx_producer_loop(NetworkDevice netdev);
        void rx_consumer_loop();
        bool enable_rx_loop = true;
        SynchronizedQueue<Tins::Packet> frame_queue;
};