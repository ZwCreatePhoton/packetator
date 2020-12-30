#include <utils.h>
#include "PcapReplayNetworkStack/pcap_replay_network_stack.h"

static const std::regex FTP_REPLY_PASSIVE_ADDRESS(R"((\d\d?\d?) *, *(\d\d?\d?) *, *(\d\d?\d?) *, *(\d\d?\d?) *, *(\d\d?\d?) *, *(\d\d?\d?))"); // captures: h1, h2, h3, h4, p1, p2
static const std::regex FTP_REPLY_BANNER_ADDRESS(R"((\d\d?\d?) *\. *(\d\d?\d?) *\. *(\d\d?\d?) *\. *(\d\d?\d?))"); // captures: h1, h2, h3, h4, p1, p2
static const std::regex FTP_REQUEST_EPRT_ADDRESS(R"(EPRT \|\d\|([\w.:]+)\|(\d\d?\d?\d?\d?))"); // captures: ip address, port

void PcapReplayNetworkStack::refresh_tcp_rewrite_map_ftp(TcpConnection *complete_original_connection)
{
    bool is_server = complete_original_connection->server_ip() == convert_ip_address(netdev.ip_address, false);
    auto &application = (FtpApplication &)(is_server ? complete_original_connection->server_application() : complete_original_connection->client_application());
    auto &rewrite_map = tcp_rewrite_maps[complete_original_connection];

    if (is_server)
    {
        if (config.modify_ftp_reply_banner_ip)
        {
            //TODO: ipv6

            auto replys = application.replys();
            for (auto &replyr : replys)
            {
                auto &reply = replyr.get();
                if (reply.code() == "220") // banner
                {
                    assert(netdev.ip_address.find('.') != std::string::npos);

                    std::string reply_str = reply.serialized();
                    std::smatch match = std::smatch();
                    if (std::regex_search(reply_str, match, FTP_REPLY_BANNER_ADDRESS))
                    {
                        std::string h1 = match.str(1);
                        uint32_t h1_offset = reply.offset + match.position(1);
                        std::string h2 = match.str(2);
                        uint32_t h2_offset = reply.offset + match.position(2);
                        std::string h3 = match.str(3);
                        uint32_t h3_offset = reply.offset + match.position(3);
                        std::string h4 = match.str(4);
                        uint32_t h4_offset = reply.offset + match.position(4);
                        std::tuple<uint32_t, uint32_t> h1_key(1 + h1_offset, h1.length());
                        std::tuple<uint32_t, uint32_t> h2_key(1 + h2_offset, h2.length());
                        std::tuple<uint32_t, uint32_t> h3_key(1 + h3_offset, h3.length());
                        std::tuple<uint32_t, uint32_t> h4_key(1 + h4_offset, h4.length());
                        // TODO: handle partial overlap with another entry in rewrite_map
                        if (rewrite_map.count(h1_key) != 0 ||
                            rewrite_map.count(h2_key) != 0 ||
                            rewrite_map.count(h3_key) != 0 ||
                            rewrite_map.count(h4_key) != 0)
                        {
                            continue;
                        }
                        std::vector<uint8_t> h1_old(h1.begin(), h1.end());
                        std::vector<uint8_t> h2_old(h2.begin(), h2.end());
                        std::vector<uint8_t> h3_old(h3.begin(), h3.end());
                        std::vector<uint8_t> h4_old(h4.begin(), h4.end());
                        std::vector<std::string> ip_parts = split(netdev.ip_address, ".");
                        assert(ip_parts.size() == 4);
                        std::vector<uint8_t> h1_new(ip_parts[0].begin(), ip_parts[0].end());
                        std::vector<uint8_t> h2_new(ip_parts[1].begin(), ip_parts[1].end());
                        std::vector<uint8_t> h3_new(ip_parts[2].begin(), ip_parts[2].end());
                        std::vector<uint8_t> h4_new(ip_parts[3].begin(), ip_parts[3].end());
                        rewrite_map[h1_key] = std::make_pair(h1_old, h1_new);
                        rewrite_map[h2_key] = std::make_pair(h2_old, h2_new);
                        rewrite_map[h3_key] = std::make_pair(h3_old, h3_new);
                        rewrite_map[h4_key] = std::make_pair(h4_old, h4_new);
                    }
                }
            }
        }
        if (config.modify_ftp_reply_passive_ip || config.modify_ftp_reply_passive_port)
        {
            auto replys = application.replys();
            for (auto &replyr : replys)
            {
                auto &reply = replyr.get();
                if (reply.code() == "227") // PASV reply
                {
                    // 227 implies IPv4 so we're going to assume that's the case
                    assert(netdev.ip_address.find('.') != std::string::npos);

                    std::string reply_str = reply.serialized();
                    std::smatch match = std::smatch();
                    if (std::regex_search(reply_str, match, FTP_REPLY_PASSIVE_ADDRESS))
                    {
                        std::string h1 = match.str(1);
                        uint32_t h1_offset = reply.offset + match.position(1);
                        std::string h2 = match.str(2);
                        uint32_t h2_offset = reply.offset + match.position(2);
                        std::string h3 = match.str(3);
                        uint32_t h3_offset = reply.offset + match.position(3);
                        std::string h4 = match.str(4);
                        uint32_t h4_offset = reply.offset + match.position(4);
                        std::string p1 = match.str(5);
                        uint32_t p1_offset = reply.offset + match.position(5);
                        std::string p2 = match.str(6);
                        uint32_t p2_offset = reply.offset + match.position(6);
                        if (config.modify_ftp_reply_passive_ip)
                        {
                            std::tuple<uint32_t, uint32_t> h1_key(1 + h1_offset, h1.length());
                            std::tuple<uint32_t, uint32_t> h2_key(1 + h2_offset, h2.length());
                            std::tuple<uint32_t, uint32_t> h3_key(1 + h3_offset, h3.length());
                            std::tuple<uint32_t, uint32_t> h4_key(1 + h4_offset, h4.length());
                            // TODO: handle partial overlap with another entry in rewrite_map
                            if (    rewrite_map.count(h1_key) != 0 ||
                                    rewrite_map.count(h2_key) != 0 ||
                                    rewrite_map.count(h3_key) != 0 ||
                                    rewrite_map.count(h4_key) != 0 )
                            {
                                continue;
                            }
                            std::vector<uint8_t> h1_old(h1.begin(), h1.end());
                            std::vector<uint8_t> h2_old(h2.begin(), h2.end());
                            std::vector<uint8_t> h3_old(h3.begin(), h3.end());
                            std::vector<uint8_t> h4_old(h4.begin(), h4.end());
                            std::vector<std::string> ip_parts = split(netdev.ip_address, ".");
                            assert(ip_parts.size() == 4);
                            std::vector<uint8_t> h1_new(ip_parts[0].begin(), ip_parts[0].end());
                            std::vector<uint8_t> h2_new(ip_parts[1].begin(), ip_parts[1].end());
                            std::vector<uint8_t> h3_new(ip_parts[2].begin(), ip_parts[2].end());
                            std::vector<uint8_t> h4_new(ip_parts[3].begin(), ip_parts[3].end());
                            rewrite_map[h1_key] = std::make_pair(h1_old, h1_new);
                            rewrite_map[h2_key] = std::make_pair(h2_old, h2_new);
                            rewrite_map[h3_key] = std::make_pair(h3_old, h3_new);
                            rewrite_map[h4_key] = std::make_pair(h4_old, h4_new);
                        }
                        if (config.modify_ftp_reply_passive_port)
                        {
                            ;
                        }
                    }
                }
            }
        }
    }
    else
    {
        if (config.modify_ftp_request_passive_ip || config.modify_ftp_request_passive_port)
        {
            auto requests = application.requests();
            for (auto &requestr : requests)
            {
                auto &request = requestr.get();
                if (request.command() == "PORT")
                {
                    // PORT implies IPv4 so we're going to assume that's the case
                    assert(netdev.ip_address.find('.') != std::string::npos);

                    std::string request_str = request.serialized();
                    std::smatch match = std::smatch();
                    if (std::regex_search(request_str, match, FTP_REPLY_PASSIVE_ADDRESS))
                    {
                        std::string h1 = match.str(1);
                        uint32_t h1_offset = request.offset + match.position(1);
                        std::string h2 = match.str(2);
                        uint32_t h2_offset = request.offset + match.position(2);
                        std::string h3 = match.str(3);
                        uint32_t h3_offset = request.offset + match.position(3);
                        std::string h4 = match.str(4);
                        uint32_t h4_offset = request.offset + match.position(4);
                        std::string p1 = match.str(5);
                        uint32_t p1_offset = request.offset + match.position(5);
                        std::string p2 = match.str(6);
                        uint32_t p2_offset = request.offset + match.position(6);
                        if (config.modify_ftp_request_passive_ip)
                        {
                            std::tuple<uint32_t, uint32_t> h1_key(1 + h1_offset, h1.length());
                            std::tuple<uint32_t, uint32_t> h2_key(1 + h2_offset, h2.length());
                            std::tuple<uint32_t, uint32_t> h3_key(1 + h3_offset, h3.length());
                            std::tuple<uint32_t, uint32_t> h4_key(1 + h4_offset, h4.length());
                            // TODO: handle partial overlap with another entry in rewrite_map
                            if (rewrite_map.count(h1_key) != 0 ||
                                rewrite_map.count(h2_key) != 0 ||
                                rewrite_map.count(h3_key) != 0 ||
                                rewrite_map.count(h4_key) != 0)
                            {
                                continue;
                            }
                            std::vector<uint8_t> h1_old(h1.begin(), h1.end());
                            std::vector<uint8_t> h2_old(h2.begin(), h2.end());
                            std::vector<uint8_t> h3_old(h3.begin(), h3.end());
                            std::vector<uint8_t> h4_old(h4.begin(), h4.end());
                            std::vector<std::string> ip_parts = split(netdev.ip_address, ".");
                            assert(ip_parts.size() == 4);
                            std::vector<uint8_t> h1_new(ip_parts[0].begin(), ip_parts[0].end());
                            std::vector<uint8_t> h2_new(ip_parts[1].begin(), ip_parts[1].end());
                            std::vector<uint8_t> h3_new(ip_parts[2].begin(), ip_parts[2].end());
                            std::vector<uint8_t> h4_new(ip_parts[3].begin(), ip_parts[3].end());
                            rewrite_map[h1_key] = std::make_pair(h1_old, h1_new);
                            rewrite_map[h2_key] = std::make_pair(h2_old, h2_new);
                            rewrite_map[h3_key] = std::make_pair(h3_old, h3_new);
                            rewrite_map[h4_key] = std::make_pair(h4_old, h4_new);
                        }
                        if (config.modify_ftp_request_passive_port)
                        {
                            ;
                        }
                    }
                }
                else if (request.command() == "EPRT")
                {
                    std::string request_str = request.serialized();
                    std::smatch match = std::smatch();
                    if (std::regex_search(request_str, match, FTP_REQUEST_EPRT_ADDRESS))
                    {
                        std::string ip = match.str(1);
                        uint32_t ip_offset = request.offset + match.position(1);
                        std::string port = match.str(2);
                        uint32_t port_offset = request.offset + match.position(2);
                        if (config.modify_ftp_request_passive_ip)
                        {
                            std::tuple<uint32_t, uint32_t> ip_key(1 + ip_offset, ip.length());
                            // TODO: handle partial overlap with another entry in rewrite_map
                            if (rewrite_map.count(ip_key) != 0)
                            {
                                continue;
                            }
                            std::vector<uint8_t> ip_old(ip.begin(), ip.end());
                            std::vector<uint8_t> ip_new(netdev.ip_address.begin(), netdev.ip_address.end());
                            rewrite_map[ip_key] = std::make_pair(ip_old, ip_new);
                        }
                        if (config.modify_ftp_request_passive_port)
                        {
                            ;
                        }
                    }
                }
            }
        }
    }
}
