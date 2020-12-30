#!/usr/bin/python3.8


def nics_menu():
    FILENAME = "nics.yaml"
    SWITCHES = "-n/--nics"
    DESCRIPTION = "YAML file that contains the configuration for the interfaces to use"
    REQUIRED = "always"

    TEMPLATE = """nics: # number of nics needs to equal to 2
"""
    NIC_TEMPLATE = """  - name: "{}" # name of the interface
    subnet: "{}" # IPv4 subnet in CIDR notation
    subnet_v6: "{}" # IPv6 subnet in CIDR notation
    gateway: "{}" # default IPv4 gateway
    gateway_v6: "{}" # default IPv6 gateway
    last_bytes_v6: 0x{} # last bytes of the random ip addresses used ; Needs to match at least the last 3 bytes of an IPv6 address assigned to this interface (only if promiscuous mode is not enabled, otherwise this can be whatever)    
"""

    print("Switches: " + SWITCHES)
    print("Description: " + DESCRIPTION)
    print("Required when: " + REQUIRED)
    filename = input("filename? (default='{}'): ".format(FILENAME))
    if not filename:
        filename = FILENAME

    config_content = TEMPLATE

    for i in range(2):
        name = input("nic #{} interface name?: ".format(i+1))
        subnetv4 = input("nic #{} ipv4 subnet? (10.2.3.4/16): ".format(i+1))
        subnetv6 = input("nic #{} ipv6 subnet? (fe80::aaaa:bbbb/64): ".format(i+1))
        gatewayv4 = input("nic #{} ipv4 gateway? (10.2.3.4): ".format(i+1))
        gatewayv6 = input("nic #{} ipv6 gateway? (fe80::aaaa:bbbb): ".format(i+1))
        prom_mode = input("does the network for nic #{} support promiscuous mode? (Y/N): ".format(i+1))
        last6 = ""
        if prom_mode == "N":
            last6 = input("last 3 bytes of an IPv6 address assigned to nic #{}? (dead12): ".format(i + 1))
        else:
            last6 = "000000"
        nici = NIC_TEMPLATE.format(name, subnetv4, subnetv6, gatewayv4, gatewayv6, last6)
        config_content += nici

    with open(filename, "w") as f:
        f.write(config_content)
        print("[+] saved {}".format(filename))

def blacklist_menu():
    FILENAME = "blacklist.yaml"
    SWITCHES = "-b/--blacklist"
    DESCRIPTION = "YAML file that contains other hosts on the network to blacklist (excludes gateways)"
    REQUIRED = "--ccm FiveTuple is not specified. Note that if there is UDP/TCP proxy inline --ccm FiveTuple MUST NOT be specified when a connection's 5-tuples differ on either side of the proxy"

    print("Switches: " + SWITCHES)
    print("Description: " + DESCRIPTION)
    print("Required when: " + REQUIRED)
    filename = input("filename? (default='{}'): ".format(FILENAME))
    if not filename:
        filename = FILENAME

    config_content = "--\n"
    print("Enter mac addresses to blacklist. Don't enter the address of the gateway(s)")
    print("Enter '0' to stop")
    config_content += "mac:\n"
    while True:
        addr = input("mac address? (00:50:56:aa:bb:cc): ")
        if addr == '0':
            break
        if addr == '':
            continue
        config_content += '  - "{}"\n'.format(addr)
    print("Enter IPv4 addresses to blacklist. Don't enter the address(es) of the gateway(s)")
    print("Enter '0' to stop")
    config_content += "ipv4:\n"
    while True:
        addr = input("ipv4 address? (10.2.3.4): ")
        if addr == '0':
            break
        if addr == '':
            continue
        config_content += '  - "{}"\n'.format(addr)
    print("Enter IPv6 addresses to blacklist. Don't enter the address(es) of the gateway(s)")
    print("Enter '0' to stop")
    config_content += "ipv6:\n"
    while True:
        addr = input("ipv6 address? (fe80::aaaa:bbbb): ")
        if addr == '0':
            break
        if addr == '':
            continue
        config_content += '  - "{}"\n'.format(addr)

    with open(filename, "w") as f:
        f.write(config_content)
        print("[+] saved {}".format(filename))

def modes_menu():
    FILENAME = "modes.csv"
    SWITCHES = "-m/--modes"
    DESCRIPTION = "CSV file that contains mode exceptions (min & max) on a per pcap basis"
    REQUIRED = "a pcap should be replayed in a mode that differs from the mode specified with -dm/--dmode"

    print("Switches: " + SWITCHES)
    print("Description: " + DESCRIPTION)
    print("Required when: " + REQUIRED)
    filename = input("filename? (default='{}'): ".format(FILENAME))
    if not filename:
        filename = FILENAME

    config_content = ""
    while True:
        pcap_name = input("pcap_name? (example.pcap): ")
        min_mode = input("min mode? (L3/L4/L5): ")
        max_mode = input("max mode? (L3/L4/L5): ")
        entry = ",".join([pcap_name, min_mode, max_mode])
        config_content += entry + "\n"
        more_exceptions = input("Any more exceptions? (Y/N): ")
        if more_exceptions == "N":
            break
    with open(filename, "w") as f:
        f.write(config_content)
        print("[+] saved {}".format(filename))


def main_menu():
    print("Main Menu:")
    print("1. nics file (-n/--nics)")
    print("2. blacklist file (-b/--blacklist)")
    print("3. modes file (-m/--modes)")

    choice = input("Please make a choice: ")

    if choice == "1":
        nics_menu()
    elif choice == "2":
        blacklist_menu()
    elif choice == "3":
        modes_menu()

    main_menu()


if __name__ == '__main__':
    main_menu()
