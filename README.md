<div align="center">
 <h3>Packetator</h3>

  <p>
    Stateful packet replayer
  </p>
</div>


<!-- TABLE OF CONTENTS -->
<details open="open">
  <summary><h2 style="display: inline-block">Table of Contents</h2></summary>
  <ol>
    <li><a href="#about-the-project">About The Project</a></li>
    <li><a href="#getting-started">Getting Started</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#contact">Contact</a></li>
  </ol>
</details>



<!-- ABOUT THE PROJECT -->
## About The Project

The Packetator project is a stateful packet replayer that utilizes
context from the network, transport, and application layers to
determine the success of a packet replay.

The Packetator project consists of two programs: 
_packetator_ and _packetatortots_.

[_packetator_](https://github.com/ZwCreatePhoton/packetator)
is a C++ program that implements the packet replayer for a single
pcap. The replay of a pcap consists of 1 or more _packetator_
instances located across 1 or more machines. Each instance
will replicate the traffic of a partition of the set of
hosts from the pcap. _packetator_ can also be used to replay
traffic from a single host to serve up content to a live client.
This program is typically not used directly since it's CLI syntax
is verbose.

[_packetatortots_](https://github.com/ZwCreatePhoton/packetatortots)
is a Python3 script that wraps around _packetator_ to replay
collections of pcaps using a relatively simple CLI syntax.
_packetatortots_ is located in a separate
[repo](https://github.com/ZwCreatePhoton/packetatortots).

## Getting Started

To get a local instance up and running, see the [setup documentation](doc/setup.md).

To learn about _packetator_'s configuration, see the [configuration documentation](doc/configuration.md).

For usage, refer to the [usage documentation](doc/usage.md).

<b>Note</b>: Usage of the _packetator_ program directly should be reserved for advanced usage.
For typical usage, use [_packetatortots_](https://github.com/ZwCreatePhoton/packetatortots).


<!-- LICENSE -->
## License

Distributed under the MIT License. See [`LICENSE`](LICENSE) for more information.

Attributions for the software redistributed with packetator can be found in the [documentation](doc/notice).

## Contact

ZwCreatePhoton - [@ZwCreatePhoton](https://twitter.com/ZwCreatePhoton)

Project Link: [https://github.com/ZwCreatePhoton/packetator](https://github.com/ZwCreatePhoton/packetator)
