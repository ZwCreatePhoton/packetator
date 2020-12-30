#include "application.h"
#include "application_classifier.h"
#include "TCPIPNetworkStack/Application/http_application.h"

class DynamicApplication : public Application
{
    public:
        DynamicApplication() = default;
        explicit DynamicApplication(Application &application);
//        DynamicApplication(DynamicApplication &application) : DynamicApplication(static_cast<Application &>(application)) {}
        void update_rx(std::vector<uint8_t> &segment) override;
        void update_tx(std::vector<uint8_t> &segment) override;
        [[nodiscard]] Protocol protocol() override;
        [[nodiscard]] Application *underlaying_application();

    private:
        Protocol _protocol = UNKNOWN;
        void update_protocol();

        std::unique_ptr<Application> underlaying_app = nullptr;
};