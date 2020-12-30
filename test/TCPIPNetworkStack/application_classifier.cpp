#include "gtest/gtest.h"

#include "TCPIPNetworkStack/Application/application_classifier.h"

TEST(ApplicationClassifier, FTP1a)
{
    //Arrange
    std::string rx_str = "220 (someFTP 1.0)\r\n";
    std::string tx_str = "USER bob\r\n";
    std::vector<uint8_t> rx_bytes(rx_str.begin(), rx_str.end());
    std::vector<uint8_t> tx_bytes(tx_str.begin(), tx_str.end());

    //Act
    auto result = ApplicationClassifier::guess(rx_bytes, tx_bytes);

    //Assert
    EXPECT_EQ (result, Application::FTP);
}

TEST(ApplicationClassifier, FTP1b)
{
    //Arrange
    std::string tx_str = "220 (someFTP 1.0)\r\n";
    std::string rx_str = "USER bob\r\n";
    std::vector<uint8_t> rx_bytes(rx_str.begin(), rx_str.end());
    std::vector<uint8_t> tx_bytes(tx_str.begin(), tx_str.end());

    //Act
    auto result = ApplicationClassifier::guess(rx_bytes, tx_bytes);

    //Assert
    EXPECT_EQ (result, Application::FTP);
}
