#pragma once

struct Stream
{
    std::string client_address;
    std::string server_address;
    uint16_t client_port;
    uint16_t server_port;
    std::vector<uint8_t> client_payload{};
    std::vector<uint8_t> server_payload{};
};
