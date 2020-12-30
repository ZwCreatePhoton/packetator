#include <PcapReplayNetworkStack/pcap_replay_network_stack.h>

void PcapReplayNetworkStack::refresh_udp_rewrite_map_dns(UdpConnection *complete_original_connection)
{
    bool is_server = complete_original_connection->server_ip() == convert_ip_address(netdev.ip_address, false);
    auto &application = (DnsApplication & )(is_server ? complete_original_connection->server_application()
                                                      : complete_original_connection->client_application());
    auto &rewrite_map = udp_rewrite_maps[complete_original_connection];

    if (is_server)
    {
        if (config.modify_dns_response_tid)
        {
            // Let's just assume this, it makes things easier. This should be the case for DNS flows anyways...
            assert(application.requests().size() <= 1 && application.responses().size() <= 1);

            UdpConnection *original_connection = (UdpConnection *)original_connection_table.lookup(complete_original_connection->client_server_five_tuple());
            if (original_connection != nullptr)
            {
                UdpConnection *replayed_connection = (UdpConnection *)convert_Connection(original_connection, true);
                if (replayed_connection != nullptr)
                {
                    auto &replayed_application = (DnsApplication & ) replayed_connection->server_application();
                    auto requests = replayed_application.requests();
                    auto responses = application.responses();
                    assert(requests.size() <= responses.size());
                    uint32_t dcount = 0;
                    for (auto &request : requests)
                    {
                        auto &response = responses[dcount];
                        std::vector<uint8_t> request_serialized = request.serialize();
                        std::vector<uint8_t> response_serialized = response.serialize();
                        std::tuple<uint32_t, uint16_t, uint16_t> key(dcount, 0, 2);
                        dcount++;
                        if (rewrite_map.count(key) != 0)
                        {
                            continue;
                        }
                        std::vector<uint8_t> bytes_old(response_serialized.begin() + std::get<1>(key), response_serialized.begin() + std::get<1>(key) + std::get<2>(key));
                        std::vector<uint8_t> bytes_new(request_serialized.begin() + std::get<1>(key), request_serialized.begin() + std::get<1>(key) + std::get<2>(key));
                        rewrite_map[key] = std::make_pair(bytes_old, bytes_new);
                    }
                }
            }
        }
    }
    else
    {
        if (config.modify_dns_request_tid)
        {
            auto requests = application.requests();
            uint32_t dcount = 0;
            for (auto &request : requests)
            {
                std::vector<uint8_t> serialized = request.serialize();
                std::tuple<uint32_t, uint16_t, uint16_t> key(dcount, 0, 2);
                dcount++;
                if (rewrite_map.count(key) != 0)
                {
                    continue;
                }
                std::vector<uint8_t> bytes_old(serialized.begin() + std::get<1>(key), serialized.begin() + std::get<1>(key) + std::get<2>(key));
                std::vector<uint8_t> bytes_new(std::get<2>(key));
                std::generate(bytes_new.begin(), bytes_new.end(), std::rand);
                rewrite_map[key] = std::make_pair(bytes_old, bytes_new);
            }
        }
    }
}