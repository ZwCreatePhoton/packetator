#include <memory>

#include <customhttparser/http.h>
#include <customhttparser/message_parser.h>

#include "application.h"

#pragma once

/*
 * Generic HTTP client & server application
 */

class HttpApplication : public Application
{
    public:
        explicit HttpApplication(Application &application);

        void update_rx(std::vector<uint8_t> &segment) override;
        void update_tx(std::vector<uint8_t> &segment) override;
        [[nodiscard]] Protocol protocol() override;
        [[nodiscard]] std::vector<std::reference_wrapper<HTTP::Message>> requests();
        [[nodiscard]] std::vector<std::reference_wrapper<HTTP::Message>> responses();

    private:
        HTTP::MessageParser rx_parser;
        HTTP::MessageParser tx_parser;
};