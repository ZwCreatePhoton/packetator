#include <vector>
#include <cstdint>
#include <cassert>
#include <string>

#pragma once

class Application
{
    public:
        enum Protocol
        {
            UNKNOWN = 0,
            HTTP,
            DNS,
            FTP
        };

        Application() = default;
        Application(bool is_server);
        Application(Application &application);
        // payload will contain the NEW data. Data from previous calls will not present. Receiving length = 0 for both will translate to the closing of the stream
        virtual void update_rx(std::vector<uint8_t> &segment);
        virtual void update_tx(std::vector<uint8_t> &segment);

        [[nodiscard]] virtual Protocol protocol();
        [[nodiscard]] bool is_server();

        // history of all the segments (segment := std::vector<uint8_t>) this application has received
        std::vector<std::vector<uint8_t>> buffered_rx_segments{};
        std::vector<std::vector<uint8_t>> buffered_tx_segments{};

    protected:
        bool _is_server = false;
};
