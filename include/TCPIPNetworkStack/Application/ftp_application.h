#include <memory>

#include "customftparser/request_parser.h"
#include "customftparser/reply_parser.h"

#include "application.h"

#pragma once

/*
 * Generic FTP client & server application
 */

class FtpApplication : public Application
{
    public:
        explicit FtpApplication(Application &application);

        void update_rx(std::vector<uint8_t> &segment) override;
        void update_tx(std::vector<uint8_t> &segment) override;
        [[nodiscard]] Protocol protocol() override;

        [[nodiscard]] std::vector<std::reference_wrapper<FTP::Request>> requests();
        [[nodiscard]] std::vector<std::reference_wrapper<FTP::Reply>> replys();

    private:
        FTP::RequestParser request_parser{};
        FTP::ReplyParser reply_parser{};
};