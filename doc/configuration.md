<div align="center">
 <h3>Packetator Configuration</h3>
</div>


<!-- TABLE OF CONTENTS -->
<details open="open">
  <summary><h2 style="display: inline-block">Table of Contents</h2></summary>
  <ol>
    <li>
      <a href="#command-line">Command Line</a>
    </li>
    <li>
      <a href="#filter-traffic">Filter Traffic</a>
    </li>
    <li>
      <a href="#config-settings">Config Settings</a>
    </li>
</ol>
</details>

## Command Line

```text
$ /opt/packetator/bin/packetator --help

USAGE: 

   /opt/packetator/bin/packetator  -i <ens0> ... -s <x.x.x.x/n> ... [-g
                                   <x.x.x.x>] ... [-r] [-w] [-b <yaml
                                   file>] -c <config.yaml> ... [-t <int>]
                                   -p <path/file.pcap> -m <x.x.x.x=y.y.y.y>
                                   ... -a <x.x.x.x,ens0,00:11:22:33:44:55>
                                   ... [--ccm <FourTuple|FiveTuple>] [--]
                                   [--version] [-h]


Where: 

   -i <ens0>,  --interface <ens0>  (accepted multiple times)
     (required)  NIC interface to send packets out of

   -s <x.x.x.x/n>,  --subnet <x.x.x.x/n>  (accepted multiple times)
     (required)  the subnet of the network the NIC interface connects to

   -g <x.x.x.x>,  --gateway <x.x.x.x>  (accepted multiple times)
     The default gateway for the NIC

   -r,  --routed
     Set this if there is a layer 3 device inline. The gateway(s) addresses
     should be set appropriately.

   -w,  --packet_capture
     Take packet capture.

   -b <yaml file>,  --blocklist <yaml file>
     yaml document with (mac) addresses to blocklist.

   -c <config.yaml>,  --config <config.yaml>  (accepted multiple times)
     (required)  configuration file

   -t <int>,  --timeout <int>
     timeout in seconds

   -p <path/file.pcap>,  --pcap <path/file.pcap>
     (required)  filepath to the pcap to replay

   -m <x.x.x.x=y.y.y.y>,  --map-address <x.x.x.x=y.y.y.y>  (accepted
      multiple times)
     (required)  Map IP address from the pcap to the IP address of the host
     to be simulated (format: 'x.x.x.x=y.y.y.y')

   -a <x.x.x.x,ens0,00:11:22:33:44:55>,  --address <x.x.x.x,ens0
      ,00:11:22:33:44:55>  (accepted multiple times)
     (required)  IP address of the host to be simulated followed by a comma
     "," and name of the interface to use for this host followed by
     (optionally) a comma "," and the mac address to use for this host

   --ccm <FourTuple|FiveTuple>
     Connection conversion method. Defaults to FiveTuple.

   --,  --ignore_rest
     Ignores the rest of the labeled arguments following this flag.

   --version
     Displays version information and exits.

   -h,  --help
     Displays usage information and exits.


   Packet replay tool
```

To define which interface, subnet, and gateway to use, use the -i , -s , and -g switches.
<br>
For example:
```
-i eth2 -s 10.3.0.0/16 -g 10.3.1.1
```
Specifying a gateway (`-g`) is optional unless if routing (`-r`) is used in the replay network.
<br>

More than 1 interface can be specified.
<br>
For example:
```
-i eth0 -s 10.1.0.0/16 -g 10.1.1.1 -i eth1 -s 10.2.0.0/16 -g 10.2.1.1 -i eth3 -s 10.3.0.0/16 -g 10.3.1.1
```

To replay traffic through a layer 3 device use the `-r` switch to specify that the replay network is routed.

To specify the pcap to replay use the -p switch
<br>
For example:
```
-p /pcaps/example.pcap
```
Only 1 capture file may be specified. Directories of pcaps can not be replayed. pcap can be in various file formats.

To define the mapping of IP addresses use the -m switch. This setting maps IP addresses in the pcap to IP address in the replay.
<br>
For example:
```
-m 172.1.1.10=10.1.1.10 -m 172.1.1.11=10.2.1.11 -m 172.1.1.12=10.3.1.12
```

To define which hosts to replay traffic for use the -a switch. The addresses specified should be the mapped address from the -m switch. Each address should also have the name of the interface to send traffic out of. Optionally, the mac address to use can also be specified (promiscuous mode required).
<br>
For example:
```
-a 10.1.1.10,eth0 -a 10.2.1.11,eth1,00:11:22:33:44:55
```
If IPv6 is used and if promiscuous mode is not enabled, then the network interface must have at least 1 IPv6 address assigned and all replayed IPv6 addresses must end in the same 3 last bytes as any of the IPv6 addresses assigned to the network interface.

To define how the traffic is replayed, specify a config file with the `-c` switch. Multiple `-c` switches can be used to override specific values used in preceding configs.
<br>
See the <a href="#config-settings">Config Settings</a> section below for more details.

To define a timeout (the time duration in seconds a replayed host will wait for the “expected“) use the `-t` switch. A timeout of `0` means no timeout. The program may block forever.

To save pcaps of the replayed traffic use the `-w` switch.
Pcaps saved will have the names of the form `<pcap IP>_<replayed IP>.pcap` like `172.1.1.10_10.1.1.10.pcap` and will be saved to the current working directory.

To change the method used to mpa replay connections back to connections in the pcap, use the `--ccm` switch.
<br>
The available methods are:`FourTuple`, `FiveTuple`
<br>
`FiveTuple` is more accurate, but can't be used in some cases.
<br>
`FourTuple` makes more assumptions about received traffic so can be less accurate in some cases. For example, replaying a pcap for a DHCP exploit on a replay network with Multicast traffic noise (like DHCP) will cause inaccurate replay.

To filter out incoming traffic, use the `-b` switch to specify a block YAML file.
<br>
See the <a href="#filter-traffic">Filter Traffic</a> section below for more details.
<br>
This option can be used to fix inaccurate replays with `--ccm FourTuple`


## Filter Traffic

Traffic on the replay network should be filtered out for the best replay accuracy.
<br>
Filtering traffic is required for some configurations. Typically, if Connection Conversion Method (CCM) is `FourTuple`, then traffic should be filtered.

For each NIC used by _packetator_, take a packet capture and let each run for a while.
```shell
ssh root@1.2.3.4 tcpdump -i eth1 -U -s0 -w - 'port !22' | wireshark -k -i -
```
```shell
ssh root@1.2.3.4 tcpdump -i eth2 -U -s0 -w - 'port !22' | wireshark -k -i -
```

Take note of addresses in any of the multicast Ethernet traffic, multicast IPv4 traffic, and multicast IPv6 traffic. (Exclude ARP & NDP)
<br>
Include the addresses to filter in a YAML file with the format:
```yaml
---
mac:
  - "00:50:cc:cc:cc:25"
  - "00:50:cc:dd:cc:25"
  - "00:50:ee:dd:cc:44"
ipv4:
  - "10.2.56.1"
  - "10.2.56.6"
  - "10.1.1.100"
ipv6:
  - "fe80::7833:5454:1212:dddd"
```
Addresses of non-packetator hosts (if any) on the network(s) should be included in the blocklist to avoid IP conflicts.
<b>Don’t include the gateway in the blocklist!</b>

Use the `-b` switch to specify the block/filter YAML file.


## Config Settings

The settings that configure how _packetator_ replays traffic are specified in a config YAML file.
There are 3 predefined config files located in ```<install_dir>/share/packetator/config/```:
- L3.yaml
- L4.yaml
- L5.yaml

The available settings and their descriptions are below. Config files other than the predefined config files are typically not used.

<b>early_address_resolution</b>: perform some form of address resolution prior to replaying traffic to force fill neighbor caches. Umbrella setting to the below settings.
<br>
<b>early_address_resolution_ping</b>: transmit an ICMP echo request to all destinations (IPv4 only)
<br>
<b>early_arp</b>: transmit an ARP request to all destinations (IPv4 only)
<br>
<b>early_garp_request</b>: transmit a gratuitous ARP request before transmitting packets (IPv4 only)
<br>
<b>early_garp_reply</b>: transmit a gratuitous ARP reply before transmitting packets (IPv4 only)
<br>
<b>early_unsolicited_na</b>: transmit an unsolicited neighbor advertisement before transmitting packets (IPv6 only)

<b>stop_on_unexpected_rst</b>: stop transmitting packets if an unexpected TCP reset is received
<br>
<b>stop_on_unexpected_fin</b>: stop transmitting packets if an unexpected TCP teardown is received. Not worth the performance hit ; not compatible with modify_tcp_data

<b>remove_time_outlier_seconds</b>: the time in seconds used in conjunction with remove_time_outlier_packet
<br>
<b>remove_time_outlier_packet</b>: remove that last packet if the time delta between the last packet and the second to last packet is greater than equal to remove_time_outlier_seconds.

<b>honor_time_delta_min_microseconds</b>: the minimum amount of time (in microseconds) to sleep. if the time delta to wait is less than this, then no sleep will occur and the next packet will be sent out asap.
<br>
<b>honor_time_delta_previous_tx</b>: wait for at least the time elapsed between the current transmit packet and the previous transmit packet.

<b>tx_event_packet_count</b>: use packet count (fragment count + non fragment count) to determine when to transmit packets
<br>
<b>tx_event_datagram_count</b>: use datagram count (non fragment count + reassembled datagram count) to determine when to transmit packets (IPv4 only)

<b>tx_event_transport</b>: use L4 / Transport layer to determine when to transmit packets
<br>
<b>tx_event_packet_count_if_no_transport</b>: If no transport protocols present, then fail back to counting packets
<br>
<b>tx_event_datagram_count_if_no_transport</b>: If no transport protocols present, then fail back to counting datagrams
<br>
<b>tx_event_udp_all_connections</b>: If false, all UDP connections are considered “independent“
<br>
<b>tx_event_udp_data</b>: use UDP data to determine when to transmit packets
<br>
<b>tx_event_tcp_all_connections</b>: If false, all TCP connections are considered “independent“
<br>
<b>tx_event_tcp_segment_count</b>: use TCP segment count to determine when to transmit packets
<br>
<b>tx_event_tcp_state</b>: use TCP state to determine when to transmit packets
<br>
<b>tx_event_tcp_data</b>: use TCP data to determine when to transmit packets

<b>tx_event_udp_application</b>: use application context on protocols over UDP to determine when to transmit packets
<br>
<b>tx_event_tcp_application</b>: use application context on protocols over TCP to determine when to transmit packets
<br>
<b>tx_event_http</b>: use HTTP context to determine when to transmit packets
<br>
<b>tx_event_http_state</b>: use HTTP parser state to determine when to transmit packets
<br>
<b>tx_event_http_state_header_count_nonzero</b>: use the existence of a non-zero number of HTTP headers as an additional HTTP parser state
<br>
<b>tx_event_http_header_count_nonzero</b>: use the existence of a non-zero number of HTTP headers to determine when to transmit packets
<br>
<b>tx_event_http_header_count</b>: use the number of HTTP headers to determine when to transmit packets
<br>
<b>tx_event_http_raw_body</b>: use the raw HTTP body to determine when to transmit packets
<br>
<b>tx_event_http_normalized_body</b>: use the normalized HTTP body to determine when to transmit packets
<br>
<b>tx_event_http_normalized_body_chunking</b>: use the normalized (dechunked) HTTP body to determine when to transmit packets
<br>
<b>tx_event_dns</b>: use DNS context to determine when to transmit packets
<br>
<b>tx_event_dns_question_section</b>: use the DNS query section to determine when to transmit packets
<br>
<b>tx_event_dns_response_section</b>: use the DNS response section to determine when to transmit packets
<br>
<b>tx_event_dns_authority_section</b>: use the DNS authority section to determine when to transmit packets
<br>
<b>tx_event_dns_additional_section</b>: use the DNS additional section to determine when to transmit packets
<br>
<b>tx_event_ftp</b>: use FTP context to determine when to transmit packets
<br>
<b>tx_event_ftp_request</b>: use FTP requests to determine when to transmit packets
<br>
<b>tx_event_ftp_request_command</b>: use the command in FTP requests to determine when to transmit packets
<br>
<b>tx_event_ftp_request_arguments</b>: use the arguments in FTP requests to determine when to transmit packets
<br>
<b>tx_event_ftp_reply</b>: use FTP replies to determine when to transmit packets
<br>
<b>tx_event_ftp_reply_code</b>: use the reply code in FTP replies to determine when to transmit packets
<br>
<b>tx_event_ftp_reply_message</b>: use the reply message in FTP replies to determine when to transmit packets

<b>modify_internet</b>: modify IP / IPv6 addresses
<br>
<b>modify_transport</b>: modify L4 / transport layer
<br>
<b>modify_udp_sport_if_client</b>: randomize client’s source port
<br>
<b>modify_udp_dport_if_server</b>: correct’s destination port to the source port of the client
<br>
<b>modify_udp_dport_if_client</b>: Applicable to TFTP
<br>
<b>modify_udp_sport_if_server</b>: Applicable to TFTP
<br>
<b>modify_udp_data</b>: if true UDP data may be modified
<br>
<b>modify_udp_data_allow_shrinkage</b>: if true UDP data may decrease in size
<br>
<b>modify_udp_data_allow_growth</b>: if true UDP data may increase in size
<br>
<b>modify_tcp_sport_if_client</b>: randomize client’s source port
<br>
<b>modify_tcp_dport_if_server</b>: corrects destination port to the source port of the client
<br>
<b>modify_seq</b>: corrects sequence numbers when altering the length of tcp data
<br>
<b>modify_ack_2</b>: corrects acknowledgement numbers
<br>
<b>modify_tcp_timestamps</b>: corrects TCP timestamps
<br>
<b>modify_tcp_data</b>: if true TCP data may be modified
<br>
<b>modify_tcp_data_allow_shrinkage</b>: if true TCP data may decrease in size.
<br>
<b>modify_tcp_data_allow_growth</b>: if true TCP data may increase in size.
<br>
<b>modify_application</b>: modify application level data
<br>
<b>modify_ftp_reply_banner_ip</b>: correct the ip address in the FTP banner
<br>
<b>modify_ftp_reply_passive_ip</b>: correct the ip address in FTP replies to the PASV command
<br>
<b>modify_ftp_request_passive_ip</b>: correct the ip address in FTP PORT, EPRT requests
<br>
<b>modify_dns_request_tid</b>: randomize the Transaction ID in DNS requests
<br>
<b>modify_dns_response_tid</b>: correct the Transaction ID in DNS responses to the Transaction ID of the response

