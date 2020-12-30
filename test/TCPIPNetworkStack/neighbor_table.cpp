#include "gtest/gtest.h"

#include "TCPIPNetworkStack/Internet/neighbor_table.h"


TEST(NeighborTable, Insert)
{
    //Arrange
    auto table = NeighborTable();
    auto ip = "1.2.3.4";
    auto mac = "ab:cd:ef:ab:cd:ef";

    //Act
    table.update(ip, mac);

    //Assert
    auto cached_mac = table.lookup(ip);
    EXPECT_EQ (cached_mac, mac);
}

TEST(NeighborTable, InsertSecond)
{
    //Arrange
    auto table = NeighborTable();
    auto ip1 = "1.2.3.4";
    auto mac1 = "ab:cd:ef:ab:cd:ef";
    auto ip2 = "5.6.7.8";
    auto mac2 = "fe:dc:ab:fe:dc:ab";
    table.update(ip1, mac1);

    //Act
    table.update(ip2, mac2);

    //Assert
    auto cached_mac1 = table.lookup(ip1);
    EXPECT_EQ (cached_mac1, mac1);
    auto cached_mac2 = table.lookup(ip2);
    EXPECT_EQ (cached_mac2, mac2);
}

TEST(NeighborTable, LookupExisting)
{
    //Arrange
    auto table = NeighborTable();
    auto ip = "1.2.3.4";
    auto mac = "ab:cd:ef:ab:cd:ef";
    table.update(ip, mac);

    //Act
    auto cached_mac = table.lookup(ip);

    //Assert
    EXPECT_EQ (cached_mac, mac);
}

TEST(NeighborTable, LookupNonExisting)
{
    //Arrange
    auto table = NeighborTable();
    auto ip = "1.2.3.4";

    //Act
    auto cached_mac = table.lookup(ip);

    //Assert
    EXPECT_EQ (cached_mac, "");
}

TEST(NeighborTable, Update)
{
    //Arrange
    auto table = NeighborTable();
    auto ip = "1.2.3.4";
    auto mac1 = "ab:cd:ef:ab:cd:ef";
    auto mac2 = "fe:dc:ba:fe:dc:ba";
    table.update(ip, mac1);

    //Act
    table.update(ip, mac2);

    //Assert
    auto cached_mac = table.lookup(ip);
    EXPECT_EQ (cached_mac,  mac2);
}
