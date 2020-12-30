#include <string>
#include <utility>
#include <type_traits>

#include <tins/tins.h>

#include "TCPIPNetworkStack/Application/application.h"
#include "TCPIPNetworkStack/Transport/flow.h"
#include "TCPIPNetworkStack/Transport/tuple.h"

#pragma once

class Connection
{
    protected:
        // ownership of client_app and server_app will be passed on to this object!
        explicit Connection(Tuple::ClientServerFiveTuple  cs5t);

    public:
        void disable_application_processing();

        void update(Tins::Packet &packet);
        void update(Tins::Packet &packet, std::string &destination_ip, std::string &source_ip);
        [[nodiscard]] const std::vector<uint8_t> &client_payload();
        [[nodiscard]] const std::vector<uint8_t> &server_payload();

        [[nodiscard]] Tuple::ClientServerFiveTuple client_server_five_tuple() const { return _cs5t; };
        [[nodiscard]] std::string client_ip() const { return _cs5t.client_ip; };
        [[nodiscard]] std::string server_ip() const { return _cs5t.server_ip; };
        [[nodiscard]] uint16_t client_port() const { return _cs5t.client_port; };
        [[nodiscard]] uint16_t server_port() const { return _cs5t.server_port; };
        [[nodiscard]] uint8_t protocol() const { return _cs5t.protocol; };

        [[nodiscard]] Application &client_application() { return *_client_application; };
        [[nodiscard]] Application &server_application() { return *_server_application; };
        template <typename T1 = Application>
        std::enable_if_t<std::is_base_of_v<Application, T1>, void>
        set_client_application_type()
        {
            _client_application.reset(new T1(*_client_application));
        }
        template <typename T1 = Application>
        std::enable_if_t<std::is_base_of_v<Application, T1>, void>
        set_server_application_type()
        {
            _server_application.reset(new T1(*_server_application));
        }

        [[nodiscard]] virtual Flow &client_flow() = 0;
        [[nodiscard]] virtual Flow &server_flow() = 0;

        [[nodiscard]] bool updates();
        void clear_updates();

    protected:
        // Forward data to the application layer
        // similar to the data passed to/returned from the "send"/"recv" socket functions
        virtual void update_application(Tins::Packet &packet);
        bool enable_application_processing = true;

    private:
        bool _updates = true;
        const Tuple::ClientServerFiveTuple _cs5t;
        std::unique_ptr<Application> _client_application;
        std::unique_ptr<Application> _server_application;
        unsigned long client_payload_size_cache = 0;
        unsigned long server_payload_size_cache = 0;
};
