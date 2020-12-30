#include <memory>

#include <tins/tins.h>

#include "application.h"

#pragma once

/*
 * Generic DNS client & server application
 */

class DnsApplication : public Application
{
    public:
        explicit DnsApplication(Application &application);

        void update_rx(std::vector<uint8_t> &segment) override;
        void update_tx(std::vector<uint8_t> &segment) override;
        [[nodiscard]] Protocol protocol() override;
        [[nodiscard]] std::vector<Tins::DNS> requests();
        [[nodiscard]] std::vector<Tins::DNS> responses();

    private:
        std::vector<Tins::DNS> rx_messages{};
        std::vector<Tins::DNS> tx_messages{};
};
