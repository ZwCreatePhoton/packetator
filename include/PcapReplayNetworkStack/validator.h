#include <string>
#include <vector>

#include <tins/tcp_ip/stream_follower.h>

#include "TCPIPNetworkStack/Transport/TCP/tcp_reassembler.h"

class Validator
{
    public:
        Validator(std::map<std::string, std::string> &, const std::string&, std::initializer_list<std::string>);

        bool GetVerdict(); // returns true if the pcap was replayed correctly

    private:
        std::map<std::string, std::string> &pcap_ip_map;
        std::string original_pcap;
        std::vector<std::string> replayed_pcaps{};

        static bool equal_streams(const Stream&, const Stream&);
};