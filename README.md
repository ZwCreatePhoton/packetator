<!--
*** Thanks for checking out the Best-README-Template. If you have a suggestion
*** that would make this better, please fork the repo and create a pull request
*** or simply open an issue with the tag "enhancement".
*** Thanks again! Now go create something AMAZING! :D
***
***
***
*** To avoid retyping too much info. Do a search and replace for the following:
*** CreatePhotonW, packetator, @CreatePhotonW, email, Packetator, Stateful packet replayer
-->



<!-- PROJECT SHIELDS -->
<!--
*** I'm using markdown "reference style" links for readability.
*** Reference links are enclosed in brackets [ ] instead of parentheses ( ).
*** See the bottom of this document for the declaration of the reference variables
*** for contributors-url, forks-url, etc. This is an optional, concise syntax you may use.
*** https://www.markdownguide.org/basic-syntax/#reference-style-links
-->
<!--
[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]
[![MIT License][license-shield]][license-url]
[![LinkedIn][linkedin-shield]][linkedin-url]
-->


<!-- PROJECT LOGO -->
<br />
<p align="center">
  <a href="https://github.com/CreatePhotonW/packetator">
    <img src="tots.png" alt="Logo" width="100" height="100"> 
  </a>

  <h3 align="center">Packetator</h3>

  <p align="center">
    Stateful packet replayer
    <br />
    <a href="https://github.com/CreatePhotonW/packetator/tree/main/docs"><strong>Explore the docs »</strong></a>
    <br />
    <br />
    <!--
    <a href="https://github.com/CreatePhotonW/packetator">View Demo</a>
    ·
    -->
    <a href="https://github.com/CreatePhotonW/packetator/issues">Report Bug</a>
    ·
    <a href="https://github.com/CreatePhotonW/packetator/issues">Request Feature</a>
  </p>
</p>



<!-- TABLE OF CONTENTS -->
<details open="open">
  <summary><h2 style="display: inline-block">Table of Contents</h2></summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#Setup">Setup</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#roadmap">Roadmap</a></li>
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#contact">Contact</a></li>
  </ol>
</details>



<!-- ABOUT THE PROJECT -->
## About The Project

<!--
[![Product Name Screen Shot][product-screenshot]](https://example.com)
-->

The Packetator project is a stateful packet replayer that utilzies network layer context, transport layer context, and application layer context to determine the success of the packet replay.

Packetator consists of two programs: _packetator_ and _packetatortots.py_.

_packetator_ is a C++ program that implements the packet replayer for a single pcap. Hosts within the pcap can be replayed in a single-sided mode so that traffic is replayed only when a live host connects. This program is typically not used directly since it's CLI syntax is verbose.

_packetatortots_ is a Python3 script that wraps around _packetator_ to replay collections of pcaps using a relatively simple CLI syntax.

<!-- 
### Built With

* []()
* []()
* []()

-->



<!-- GETTING STARTED -->
## Getting Started

To get a local copy up and running follow these simple steps.

### Setup

See the doc: [Packetator_Setup.rtf](docs/Packetator_Setup.rtf)


<!-- USAGE EXAMPLES -->
## Usage
For standard usage, refer to the doc: [packetatortors.rtf](docs/packetatortots.rtf)

For advanced usage, refer to the doc: [packetator.rtf](docs/packetator.rtf)

<!-- ROADMAP -->
## Roadmap

See the [open issues](https://github.com/CreatePhotonW/packetator/issues) for a list of proposed features (and known issues).



<!-- CONTRIBUTING -->
## Contributing

Contributions are what make the open source community such an amazing place to be learn, inspire, and create. Any contributions you make are **greatly appreciated**.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request



<!-- LICENSE -->
## License

Distributed under the MIT License. See `LICENSE` for more information.



<!-- CONTACT -->
## Contact

CreatePhotonW - [@CreatePhotonW](https://twitter.com/CreatePhotonW)

Project Link: [https://github.com/CreatePhotonW/packetator](https://github.com/CreatePhotonW/packetator)



<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->
[contributors-shield]: https://img.shields.io/github/contributors/CreatePhotonW/repo.svg?style=for-the-badge
[contributors-url]: https://github.com/CreatePhotonW/repo/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/CreatePhotonW/repo.svg?style=for-the-badge
[forks-url]: https://github.com/CreatePhotonW/repo/network/members
[stars-shield]: https://img.shields.io/github/stars/CreatePhotonW/repo.svg?style=for-the-badge
[stars-url]: https://github.com/CreatePhotonW/repo/stargazers
[issues-shield]: https://img.shields.io/github/issues/CreatePhotonW/repo.svg?style=for-the-badge
[issues-url]: https://github.com/CreatePhotonW/repo/issues
[license-shield]: https://img.shields.io/github/license/CreatePhotonW/repo.svg?style=for-the-badge
[license-url]: https://github.com/CreatePhotonW/repo/blob/master/LICENSE.txt
[linkedin-shield]: https://img.shields.io/badge/-LinkedIn-black.svg?style=for-the-badge&logo=linkedin&colorB=555
[linkedin-url]: https://linkedin.com/in/CreatePhotonW
