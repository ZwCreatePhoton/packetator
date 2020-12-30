#include "gtest/gtest.h"

#include "TCPIPNetworkStack/Transport/connection_table.h"
#include "TCPIPNetworkStack/Transport/TCP/tcp_connection.h"


TEST(ConnectionTable, Insert)
{
    //Arrange
    auto table = ConnectionTable();
    Tuple::ClientServerFiveTuple cs5t1 {.client_ip = "1.2.3.4", .client_port = 12345, .server_ip = "5.6.7.8", .server_port = 80, .protocol = IPPROTO_TCP};
    auto *connection1 = new TcpConnection(cs5t1);

    //Act
    table.add(connection1);

    //Assert
    auto *entry = table.lookup(connection1->client_server_five_tuple());
    EXPECT_EQ (entry, connection1);
}

TEST(ConnectionTable, InsertSecond)
{
    //Arrange
    auto table = ConnectionTable();
    Tuple::ClientServerFiveTuple cs5t1 {.client_ip = "1.2.3.4", .client_port = 12345, .server_ip = "5.6.7.8", .server_port = 80, .protocol = IPPROTO_TCP};
    auto *connection1 = new TcpConnection(cs5t1);
    Tuple::ClientServerFiveTuple cs5t2 {.client_ip = "1.2.3.5", .client_port = 12346, .server_ip = "5.6.7.9", .server_port = 81, .protocol = IPPROTO_TCP};
    auto *connection2 = new TcpConnection(cs5t2);
    table.add(connection1);

    //Act
    table.add(connection2);

    //Assert
    auto *entry = table.lookup(connection2->client_server_five_tuple());
    EXPECT_EQ (entry, connection2);
}

TEST(ConnectionTable, LookupNonexisting)
{
    //Arrange
    auto table = ConnectionTable();
    Tuple::ClientServerFiveTuple cs5t1 {.client_ip = "1.2.3.4", .client_port = 12345, .server_ip = "5.6.7.8", .server_port = 80, .protocol = IPPROTO_TCP};

    //Act

    //Assert
    auto *entry = table.lookup(cs5t1);
    EXPECT_EQ (entry, nullptr);
}


TEST(ConnectionTable, LookupNonexistingThenInsert)
{
    //Arrange
    auto table = ConnectionTable();
    Tuple::ClientServerFiveTuple cs5t1 {.client_ip = "1.2.3.4", .client_port = 12345, .server_ip = "5.6.7.8", .server_port = 80, .protocol = IPPROTO_TCP};
    auto *connection1 = new TcpConnection(cs5t1);
    table.lookup(connection1->client_server_five_tuple());

    //Act
    table.add(connection1);

    //Assert
    auto *entry = table.lookup(cs5t1);
    EXPECT_EQ (entry, connection1);
}


TEST(ConnectionTable, lookup_10_times)
{
    //Arrange
    auto table = ConnectionTable();
    Tuple::ClientServerFiveTuple cs5t1 {.client_ip = "1.2.3.4", .client_port = 12345, .server_ip = "5.6.7.8", .server_port = 80, .protocol = IPPROTO_TCP};
    auto *connection1 = new TcpConnection(cs5t1);
    table.add(connection1);

    //Act
    auto *entry = table.lookup(connection1->client_server_five_tuple());
    entry = table.lookup(connection1->client_server_five_tuple());
    entry = table.lookup(connection1->client_server_five_tuple());
    entry = table.lookup(connection1->client_server_five_tuple());
    entry = table.lookup(connection1->client_server_five_tuple());
    entry = table.lookup(connection1->client_server_five_tuple());
    entry = table.lookup(connection1->client_server_five_tuple());
    entry = table.lookup(connection1->client_server_five_tuple());
    entry = table.lookup(connection1->client_server_five_tuple());
    entry = table.lookup(connection1->client_server_five_tuple());

    //Assert
    EXPECT_EQ (entry, connection1);
}

TEST(ConnectionTable, GetAll)
{
    //Arrange
    auto table = ConnectionTable();
    Tuple::ClientServerFiveTuple cs5t1 {.client_ip = "1.2.3.4", .client_port = 12345, .server_ip = "5.6.7.8", .server_port = 80, .protocol = IPPROTO_TCP};
    auto *connection1 = new TcpConnection(cs5t1);
    Tuple::ClientServerFiveTuple cs5t2 {.client_ip = "1.2.3.5", .client_port = 12346, .server_ip = "5.6.7.9", .server_port = 81, .protocol = IPPROTO_TCP};
    auto *connection2 = new TcpConnection(cs5t2);
    table.add(connection1);
    table.add(connection2);

    //Act
    auto *connections = table.all();

    //Assert
    EXPECT_EQ (connections->size(), 2);
    EXPECT_TRUE (std::find(connections->begin(), connections->end(), connection1) != connections->end());
    EXPECT_TRUE (std::find(connections->begin(), connections->end(), connection2) != connections->end());
}


TEST(ConnectionTable, Clear)
{
    //Arrange
    auto table = ConnectionTable();
    Tuple::ClientServerFiveTuple cs5t1 {.client_ip = "1.2.3.4", .client_port = 12345, .server_ip = "5.6.7.8", .server_port = 80, .protocol = IPPROTO_TCP};
    auto *connection1 = new TcpConnection(cs5t1);
    table.add(connection1);

    //Act
    table.clear();

    //Assert
    auto *entry = table.lookup(cs5t1);
    EXPECT_EQ (entry, nullptr);
}



