<div align="center">
 <h3>Packetator Usage</h3>
</div>


<!-- TABLE OF CONTENTS -->
<details open="open">
  <summary><h2 style="display: inline-block">Table of Contents</h2></summary>
  <ol>
    <li>
      <a href="#example-usage-1">Example Usage 1</a>
    </li>
    <li>
      <a href="#example-usage-2">Example Usage 2</a>
    </li>
    <li>
      <a href="#example-usage-3">Example Usage 3</a>
    </li>
</ol>
</details>

## Example Usage 1

#### Pcap
In this example we will replay the pcap chunked_16_mal.pcap
<br>
In this pcap, a client (10.141.41.101/24) send a GET request for an Internet Explorer exploit to an HTTP server (10.141.41.1/24).
<br>
The server declares the response chunked and sends the exploit in 16-byte chunks.

#### Replay Config
We will replay this pcap using 1 packetator node with 2 NICs (ens19, ens20) connected to a switch.
<br>
There is no layer 2 firewall, so we expect the client to receive the exploit completely unmodified.

The replay network is clear of other layer 3 hosts, so we can replay with either CCM `FourTuple` or `FiveTuple` without the need to create a block filter file (`-b`).

The following IP address map will be used:
- 10.141.41.101 -> 192.168.0.201
- 10.141.41.1 -> 192.168.0.2

We will replay in L4 mode.

#### Command:

```shell
sudo /opt/packetator/bin/packetator -t 3 -c /opt/packetator/share/packetator/config/L4.yaml -p /opt/packetator/share/doc/packetator/pcap/chunked_16_mal.pcap -m 10.141.41.101=192.168.0.201 -m 10.141.41.1=192.168.0.2 -i ens19 -s 192.168.0.0/24 -i ens20 -s 192.168.0.0/24 -a 192.168.0.201,ens19 -a 192.168.0.2,ens20 --ccm FiveTuple -w
```

#### Explanation

- `-t 3`: Set a timeout of 3 seconds for this replay. After 3 seconds the replay will be terminated if it hung.
- `-c /opt/packetator/share/packetator/config/L4.yaml`: Use the config file for L4 mode.
- `-p /opt/packetator/share/doc/packetator/pcap/chunked_16_mal.pcap`: Replay our desired pcap.
- `-m 10.141.41.101=192.168.0.201 -m 10.141.41.1=192.168.0.2`: Specify our desired IP address mapping.
- `-i ens19 -s 192.168.0.0/24 -i ens20 -s 192.168.0.0/24`: Define the network for each NIC used.
- `-a 192.168.0.201,ens19 -a 192.168.0.2,ens20`: Specify that we want the server (192.168.0.2) to use ens20 and the client (192.168.0.201) to use ens19.
- `--ccm FiveTuple`: Replay the traffic using the `FiveTuple` CCM. `FourTuple` also would have been acceptable here and produced the same traffic.
- `-w`: Save the replayed packets as a set of pcaps (in the Current Working Directory).

#### Result

A successful replay will print:
```text
[+]      Packet replay was successful!
```

A unsuccessful replay will print:
```text
[+]      Packet replay was not successful!
```

In this case the expected result is `Packet replay was successful`,
since there were no security controls in place.


## Example Usage 2

#### Pcap
See [Example Usage 1](#example-usage-1).

#### Replay Config
We will replay this pcap using 1 packetator node with 2 NICs (ens19, ens20) connected to a layer 2 firewall.
<br>
The firewall is configured to:
- Normalize chunked HTTP messages.
- Allow this malicious exploit.

The replay network is clear of other layer 3 hosts, so we can replay with either CCM `FourTuple` or `FiveTuple` without the need to create a block filter file (`-b`).

The following IP address map will be used:
- 10.141.41.101 -> 192.168.0.201
- 10.141.41.1 -> 192.168.0.2

We will replay in L4 mode.

#### Command:

See [Example Usage 1](#example-usage-1).

#### Explanation

See [Example Usage 1](#example-usage-1).

#### Result

In this case the expected result is `Packet replay was not successful`,
since the client received a response with no chunks.
In L4 mode, application data is expected to arrive unmodified.
Normalizing the chunked body will cause the validation to mark the replay as not successful.

If the replay were rerun in L5 mode, the replay would be validated as a success.


## Example Usage 3

#### Pcap

See [Example Usage 1](#example-usage-1).

#### Replay Config
We will replay this pcap using 1 packetator node with 2 NICs (ens19, ens20) connected to a layer 3 firewall.
<br>
The firewall is configured to:
- Normalize chunked HTTP messages.
- Allow this malicious exploit.

The firewall has the two networks:
- network 1: 192.168.1.1/24
- network 2: 192.168.0.1/24

There will also be an arbitrary host on network 2 with MAC aa:bb:cc:dd:ee:ff and multiple IP addresses.

The replay network is <b>not</b> clear of other layer 3 hosts due to aa:bb:cc:dd:ee:ff and not due to the layer 3 firewall.
We should replay with CCM `FourTuple`.
A block filter file (`-b`) may or may not be required for some firewalls and pcaps, so to be safe we'll create one anyway.

```yaml
---
mac:
  - "aa:bb:cc:dd:ee:ff"
ipv4: []
ipv6: []
```

The following IP address map will be used:
- 10.141.41.101 -> 192.168.0.101
- 10.141.41.1 -> 192.168.1.11

We will replay in L5 mode.

#### Command:

```shell
sudo /opt/packetator/bin/packetator -t 3 -c /opt/packetator/share/packetator/config/L5.yaml -p /opt/packetator/share/doc/packetator/pcap/chunked_16_mal.pcap -m 10.141.41.101=192.168.0.101 -m 10.141.41.1=192.168.0.11 -i ens19 -s 192.168.0.0/24 -g 192.168.0.1 -i ens20 -s 192.168.1.0/24 -g 192.168.1.1 -a 192.168.0.101,ens19 -a 192.168.0.11,ens20 --ccm FourTuple -w -r
```

#### Explanation

- `-t 3`: Set a timeout of 3 seconds for this replay. After 3 seconds the replay will be terminated if it hung.
- `-c /opt/packetator/share/packetator/config/L5.yaml`: Use the config file for L5 mode.
- `-p /opt/packetator/share/doc/packetator/pcap/chunked_16_mal.pcap`: Replay our desired pcap.
- `-m 10.141.41.101=192.168.0.101 -m 10.141.41.1=192.168.0.11`: Specify our desired IP address mapping.
- `-i ens19 -s 192.168.0.0/24 -g 192.168.0.1 -i ens20 -s 192.168.1.0/24 -g 192.168.1.1`: Define the network for each NIC used. Note that the gateways for each NIC had to defined with `-g`.
- `-a 192.168.0.101,ens19 -a 192.168.1.11,ens20`: Specify that we want the server (192.168.1.11) to use ens20 and the client (192.168.0.101) to use ens19.
- `--ccm FourTuple`: Replay the traffic using the `FourTuple` CCM.
- `-w`: Save the replayed packets as a set of pcaps (in the Current Working Directory).
- `-r`: The network is routed.

#### Result

In this case the expected result is `Packet replay was successful`.

