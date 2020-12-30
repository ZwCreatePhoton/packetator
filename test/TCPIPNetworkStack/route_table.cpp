#include "gtest/gtest.h"

#include "TCPIPNetworkStack/Internet/route_table.h"


TEST(RouteTable, Insert)
{
    //Arrange
    auto table = RouteTable();
    auto dst = "1.1.1.1";
    auto gateway = "2.2.2.2";
    auto netmask = "3.3.3.3";
    auto flags = 0;
    auto metric = 0;

    //Act
    table.add(dst, gateway, netmask, flags, metric);

    //Assert
    auto entry = table.lookup(dst);
    EXPECT_EQ (entry->dst, dst);
    EXPECT_EQ (entry->gateway, gateway);
    EXPECT_EQ (entry->netmask, netmask);
    EXPECT_EQ (entry->flags, flags);
    EXPECT_EQ (entry->metric, metric);
}

TEST(RouteTable, InsertSecond)
{
    //Arrange
    auto table = RouteTable();
    auto dst1 = "1.1.1.1";
    auto gateway1 = "2.2.2.2";
    auto netmask1 = "3.3.3.3";
    auto flags1 = 0;
    auto metric1 = 0;
    auto dst2 = "7.7.7.7";
    auto gateway2 = "9.9.9.9";
    auto netmask2 = "8.8.8.8";
    auto flags2 = 1;
    auto metric2 = 1;
    table.add(dst1, gateway1, netmask1, flags1, metric1);

    //Act
    table.add(dst2, gateway2, netmask2, flags2, metric2);

    //Assert
    auto entry1 = table.lookup(dst1);
    EXPECT_EQ (entry1->dst, dst1);
    EXPECT_EQ (entry1->gateway, gateway1);
    EXPECT_EQ (entry1->netmask, netmask1);
    EXPECT_EQ (entry1->flags, flags1);
    EXPECT_EQ (entry1->metric, metric1);

    auto entry2 = table.lookup(dst2);
    EXPECT_EQ (entry2->dst, dst2);
    EXPECT_EQ (entry2->gateway, gateway2);
    EXPECT_EQ (entry2->netmask, netmask2);
    EXPECT_EQ (entry2->flags, flags2);
    EXPECT_EQ (entry2->metric, metric2);
}

TEST(RouteTable, LookupExisting)
{
    //Arrange
    auto table = RouteTable();
    auto dst = "1.1.1.1";
    auto gateway = "2.2.2.2";
    auto netmask = "3.3.3.3";
    auto flags = 0;
    auto metric = 0;
    table.add(dst, gateway, netmask, flags, metric);

    //Act
    auto *entry = table.lookup(dst);

    //Assert
    EXPECT_EQ (entry->dst, dst);
    EXPECT_EQ (entry->gateway, gateway);
    EXPECT_EQ (entry->netmask, netmask);
    EXPECT_EQ (entry->flags, flags);
    EXPECT_EQ (entry->metric, metric);
}

TEST(RouteTable, LookupNonExisting)
{
    //Arrange
    auto table = RouteTable();
    auto dst = "1.1.1.1";
    auto gateway = "2.2.2.2";
    auto netmask = "3.3.3.3";
    auto flags = 0;
    auto metric = 0;

    //Act
    auto *entry = table.lookup(dst);

    //Assert
    EXPECT_EQ (entry, nullptr);
}

TEST(RouteTable, Update)
{
    //Arrange
    auto table = RouteTable();
    auto dst = "1.1.1.1";
    auto gateway1 = "2.2.2.2";
    auto gateway2 = "9.9.9.9";
    auto netmask1 = "3.3.3.3";
    auto netmask2 = "8.8.8.8";
    auto flags1 = 0;
    auto flags2 = 1;
    auto metric1 = 0;
    auto metric2 = 1;
    table.add(dst, gateway1, netmask1, flags1, metric1);

    //Act
    table.add(dst, gateway2, netmask2, flags2, metric2);

    //Assert
    auto *entry = table.lookup(dst);
    EXPECT_EQ (entry->dst, dst);
    EXPECT_EQ (entry->gateway, gateway2);
    EXPECT_EQ (entry->netmask, netmask2);
    EXPECT_EQ (entry->flags, flags2);
    EXPECT_EQ (entry->metric, metric2);
}

TEST(RouteTable, Clear)
{
    //Arrange
    auto table = RouteTable();
    auto dst = "1.1.1.1";
    auto gateway = "2.2.2.2";
    auto netmask = "3.3.3.3";
    auto flags = 0;
    auto metric = 0;
    table.add(dst, gateway, netmask, flags, metric);

    //Act
    table.clear();

    //Assert
    auto *entry = table.lookup(dst);
    EXPECT_EQ (entry, nullptr);
}
