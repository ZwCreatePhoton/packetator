#!/usr/bin/python3.8

import multiprocessing
from multiprocessing.pool import ThreadPool
import subprocess
import os.path
import ipaddress
import random
import operator
import socket
import shlex
import argparse
import zlib
import zipfile

import dpkt
import tqdm
import yaml

bin_name = "packetator"
bin_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), bin_name)
bin_path = os.path.abspath(bin_path)

results = dict()

debug = None
debug_filename = "debug.txt"
output_dir = None
timeout = None

pcap_file_extensions = [".pcap"]

modes = ["L3", "L4", "L5"]

REPLAY_SUCCESS = "replay success"
REPLAY_FAILURE = "replay failure"
REPLAY_NOT = "not replayed"

def run_packetator(arguments):
    cmd = tuple(arguments[0])
    meta = arguments[1]
    iteration_count = meta["iteration_count"]

    pcap_path_index = None
    for i in range(len(cmd)):
        if cmd[i] == "-p":
            pcap_path_index = i + 1
            break
    pcap_filepath = cmd[pcap_path_index]
    if "'" in pcap_filepath:
        pcap_filepath = pcap_filepath.split("'")[1]
    base = os.path.basename(pcap_filepath)
    pcap_output_dir = os.path.join(output_dir, base)
    try:
        os.mkdir(pcap_output_dir)
    except:
        pass
    pcap_output_dir = os.path.join(pcap_output_dir, str(iteration_count))
    try:
        os.mkdir(pcap_output_dir)
    except:
        pass

    cmdline = " ".join(c.replace(' ', '\\ ') for c in cmd) # escape spaces
    result = "unknown"
    stdout = ""
    returncode = 0
    try:
        completed_process = subprocess.run(cmd, capture_output=True, text=True, cwd=pcap_output_dir, timeout=timeout)
        stdout = completed_process.stdout
        returncode = completed_process.returncode
        if "Packet replay was successful" in stdout:
            result = REPLAY_SUCCESS
        elif "Packet replay was not successful" in stdout:
            result = REPLAY_FAILURE
            # should we retry if we end up with "replay failure" and a segmentation fault (exit code = -11)
        else:
            if returncode != 0:
                if debug:
                    result = "error (" + str(returncode) + ")"
                else:
                    result = REPLAY_FAILURE
            else:
                result = "unknown"
    except subprocess.TimeoutExpired:
        returncode = 1001
        if debug:
            result = "error (" + str(returncode) + ")"
        else:
            result = REPLAY_FAILURE

    results[cmd] = result
    with open(os.path.join(pcap_output_dir, "result.txt"), "w") as f:
        f.write(result)

    if debug:
        with open(os.path.join(pcap_output_dir, debug_filename), "w") as f:
            f.write("Cmdline: " + cmdline + "\n")
            f.write("Exit code: " + str(returncode) + "\n")
            f.write("Stdout:" + "\n")
            f.write(stdout)


# returns the number of edges connected to vertex v
def count_pairs(E, v):
    count = 0
    for e in E:
        if v in e:
            count += 1
    return count


# returns the node/vertex with the most number of edges to other nodes/vertices
def most_popular_node(V, E):
    count_map = {v: count_pairs(E, v) for v in V}  # maps host -> count
    if len(count_map) == 0:
        return None
    return max(count_map.items(), key=operator.itemgetter(1))[0]


# N = number of partitions
# V = set of vertices used to define the graph
# E = set of edges (2-tuple) that define the graph
# This assumes that N = 2
# returns a N element list of sets of hosts
# returns None if it is impossible to distribute the nodes across the N partitions
def distribute_nodes(N, V, E):
    assert N == 2
    partitions = [set() for n in range(N)]
    popular_node = most_popular_node(V, E)
    if popular_node is None:
        partitions[0].update(V)
        return partitions
    partitions[0].add(popular_node)
    processed_nodes = set()
    while any((current_node := v) not in processed_nodes for i in range(len(partitions)) for v in partitions[i]):
        current_partition_index = None
        for i in range(len(partitions)):
            if current_node in partitions[i]:
                current_partition_index = i
        for e in E:
            if e[0] == current_node:
                partitions[(current_partition_index + 1) % len(partitions)].add(e[1])
            elif e[1] == current_node:
                partitions[(current_partition_index + 1) % len(partitions)].add(e[0])
        processed_nodes.add(current_node)
    if len(V) != len(processed_nodes):
        # The remaining nodes are not connected to the already processed nodes
        V2 = {h for h in V if h not in processed_nodes}
        E2 = {p for p in E for h in processed_nodes if h not in p}
        result2 = distribute_nodes(N, V2, E2)
        if result2 is None:
            return None
        for i in range(len(partitions)):
            partitions[i].update(result2[i])
    return partitions


def test_distribute_nodes():
    test_cases = [
        (2, {}, {}),
        (2, {"A"}, {}),
        (2, {"A", "B"}, {}),
        (2, {"A", "B"}, {("A", "B")}),
        (2, {"A", "B", "C"}, {("A", "B")}),
        (2, {"A", "B", "C"}, {("A", "B"), ("B", "C")}),
        (2, {"A", "B", "C"}, {("A", "B"), ("B", "C"), ("C", "A")}),
        (2, {"A", "B", "C", "D"}, {("A", "B")}),
        (2, {"A", "B", "C", "D"}, {("A", "B"), ("B", "C")}),
        (2, {"A", "B", "C", "D"}, {("A", "B"), ("B", "C"), ("C", "A")}),
        (2, {"A", "B", "C", "D"}, {("A", "B"), ("B", "C"), ("C", "D")}),
        (2, {"A", "B", "C", "D"}, {("A", "B"), ("B", "C"), ("C", "D"), ("D", "A")}),
        (2, {"A", "B", "C", "D", "E"}, {("A", "B"), ("B", "C"), ("C", "D"), ("D", "E"), ("E", "A")}),
        (2, {"A", "B", "C", "D", "E", "F"}, {("A", "B"), ("B", "C"), ("C", "D"), ("D", "E"), ("E", "F"), ("F", "A")}),
        (2, {"A", "B", "C", "D", "E", "F", "G"},
         {("A", "B"), ("B", "C"), ("C", "D"), ("D", "E"), ("E", "F"), ("F", "G"), ("G", "A")}),
        (2, {"A", "B", "C", "D", "E", "F", "G", "H"},
         {("A", "B"), ("B", "C"), ("C", "D"), ("D", "E"), ("E", "F"), ("F", "G"), ("G", "H"), ("H", "A")}),
    ]
    for test_case in test_cases:
        N, V, E = test_case
        results = distribute_nodes(N, V, E)
        contradiction = False
        for v in V:
            partitions = [p for p in results if v in p]
            if len(partitions) > 1:
                contradiction = True
                break
        print(test_case)
        print("\t" + ("*" if contradiction else "") + str(results))


def random_bytes(num=6):
    return [random.randrange(256) for _ in range(num)]


def generate_mac(uaa=False, multicast=False, oui=None, separator=':', byte_fmt='%02x'):
    mac = random_bytes()
    if oui:
        if type(oui) == str:
            oui = [int(chunk) for chunk in oui.split(separator)]
        mac = oui + random_bytes(num=6 - len(oui))
    else:
        if multicast:
            mac[0] |= 1  # set bit 0
        else:
            mac[0] &= ~1  # clear bit 0
        if uaa:
            mac[0] &= ~(1 << 1)  # clear bit 1
        else:
            mac[0] |= 1 << 1  # set bit 1
    return separator.join(byte_fmt % b for b in mac)


def inet_to_str(inet):
    """Convert inet object to a string
        Args:
            inet (inet struct): inet network address
        Returns:
            str: Printable/readable IP address
    """
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)


# returns a 2-tuple where
# 0.) set of hosts
# 1.) set of 2-tuples of two connected hosts
def parse_pcap(pcap_path):
    H = set()
    E = set()
    with open(pcap_path, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        for timestamp, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            if isinstance(eth.data, dpkt.ip.IP) or isinstance(eth.data, dpkt.ip6.IP6):
                if isinstance(eth.data, dpkt.ip6.IP6) and eth.data.p == 58:  # skipping ICMPv6 / NDP
                    continue
                src, dst = inet_to_str(eth.data.src), inet_to_str(eth.data.dst)
                H.add(src)
                H.add(dst)
                if (src, dst) not in E and (dst, src) not in E:
                    E.add((src, dst))
            else:
                pass
    return H, E


def random_ipv4_address(subnet_string):
    subnet = ipaddress.IPv4Network(subnet_string, False)
    bits = random.getrandbits(subnet.max_prefixlen - subnet.prefixlen)
    addr = ipaddress.IPv4Address(subnet.network_address + bits)
    return str(addr)


def random_ipv6_address(subnet_string, lastbytes=b''):
    subnet = ipaddress.IPv6Network(subnet_string, False)
    bits = random.getrandbits(subnet.max_prefixlen - subnet.prefixlen - len(lastbytes) * 8)
    addr = ipaddress.IPv6Address(
        subnet.network_address + (bits << len(lastbytes) * 8) + int.from_bytes(lastbytes, "big"))
    return str(addr)


def parse_nics(nics_yaml):
    nics = []
    with open(nics_yaml) as f:
        data = yaml.load(f, Loader=yaml.FullLoader)
        for nic in data['nics']:
            nic['last_bytes_v6'] = nic['last_bytes_v6'].to_bytes((nic['last_bytes_v6'].bit_length() + 7) // 8, "big")
            nics.append(nic)
    return nics


def parse_blacklist(blacklist_yaml):
    with open(blacklist_yaml) as f:
        data = yaml.load(f, Loader=yaml.FullLoader)
        return data


if __name__ == '__main__':
    # test_distribute_nodes()
    # exit(0)

    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter, prog='packetatortots')
    parser.add_argument('--version', action='version', version='%(prog)s 1.0')
    parser.add_argument('-d', '--debug', required=False, action='store_true',
                        help='debug output ; replay errors are not treated as replay failures')
    parser.add_argument('-N', '--iterations', required=False, type=int, default=3, help='Number of iterations',
                        metavar='N')
    parser.add_argument('-t', '--timeout', required=False, type=int, default=10*60, help='Timeout to wait for the packetator subprocess to complete. Useful for when reply gets stuck in a loop',
                        metavar='seconds')
    parser.add_argument('-dm', '--dmode', required=False, type=str, choices=["MIN"] + modes + ["MAX"], default="L4",
                        help='Default mode to replay pcaps in')
    parser.add_argument('-m', '--modes', required=False, type=str, default='example_modes.csv',
                        help='Line delimited file that maps pcap filenames to a minimum and maximum mode: example.pcap,L4,L5',
                        metavar='FILE')
    parser.add_argument('-j', '--jobs', required=False, type=int, default=10 * multiprocessing.cpu_count(),
                        help='Number of pcaps to replay in parallel', metavar='N')
    parser.add_argument('-o', '--outfile', required=False, type=str, default=None,
                        help='output file, in CSV format. (Columns: pcap basename, mode, success count, number of iterations, overall result, result 1, result 2, ..., ip addresses 1, ip addresses 2, ...)', metavar='FILE')
    parser.add_argument('-od', '--outdir', required=False, default='out', help='output directory', metavar='DIR')
    parser.add_argument('-zd', '--zipdir', required=False, help='output directory to place compressed zips of any generated pcaps', metavar='DIR')
    parser.add_argument('-b', '--blacklist', required=False, help='yaml document with addresses to blacklist.',
                        metavar='FILE')
    parser.add_argument('-rm', '--randommac', required=False, action='store_true',
                        help='use random mac addresses. promiscuous mode is required ')
    parser.add_argument('-ri6', '--randomip6', required=False, action='store_true',
                        help='randomize the last 3 bytes of IPv6 addresses as well. promiscuous mode is required')
    parser.add_argument('-n', '--nics', required=True, type=str, default='example_nics.yaml',
                        help='YAML document that specifies the nic(s) to use', metavar='FILE')
    parser.add_argument("pcaps_path", help='pcap or directory of pcaps to replay')
    parser.add_argument('packetator_args', nargs='*',
                        help='"--" followed by arguments to pass along to packetator for all replays. run: "{0} --help" for more info'.format(
                            bin_name))
    args = parser.parse_args()

    timeout = args.timeout

    consumed_addresses = set()

    if args.blacklist:
        blacklist_data = parse_blacklist(args.blacklist)
        mac_bl, ipv4_bl, ipv6_bl = blacklist_data["mac"], blacklist_data["ipv4"], blacklist_data["ipv6"]
        for a in mac_bl:
            consumed_addresses.add(a)
        for a in ipv4_bl:
            consumed_addresses.add(a)
        for a in ipv6_bl:
            consumed_addresses.add(a)

        if "-b" not in args.packetator_args and "--blacklist" not in args.packetator_args:
            args.packetator_args += ["-b", os.path.abspath(args.blacklist)]

    debug = args.debug

    nics = parse_nics(args.nics)
    assert len(nics) == 2
    for nic in nics:
        if nic["gateway"]:
            consumed_addresses.add(nic["gateway"])
        if nic["gateway_v6"]:
            consumed_addresses.add(nic["gateway_v6"])

    output_dir = os.path.abspath(args.outdir)
    try:
        os.mkdir(output_dir)
    except:
        pass

    pool = ThreadPool(processes=args.jobs)

    cmdlines = []

    pcap_paths = []
    if os.path.isdir(args.pcaps_path):
        for (dirpath, dirnames, filenames) in os.walk(args.pcaps_path):
            for filename in filenames:
                if os.path.splitext(filename)[-1] in pcap_file_extensions:
                    pcap_paths.append(os.path.abspath(os.path.join(dirpath, filename)))
    else:
        if os.path.splitext(args.pcaps_path)[-1] in pcap_file_extensions:
            pcap_paths.append(os.path.abspath(args.pcaps_path))

    modes_file_map = dict()
    if args.modes is not None:
        with open(os.path.expanduser(args.modes), "r") as f:
            lines = [line.strip() for line in f.readlines() if line.strip()]
            for line in lines:
                tokens = [t.strip() for t in line.rstrip('\n').split(",")]
                if len(tokens) == 3:
                    pcap_name, min_mode, max_mode = tokens
                    if min_mode == "MIN": min_mode = modes[0]
                    if max_mode == "MAX": max_mode = modes[-1]
                    if min_mode not in modes or max_mode not in modes:
                        print("invalid line in " + args.modes + ":\n" + line)
                        exit(1)
                    modes_file_map[pcap_name] = (min_mode, max_mode)
                elif len(tokens) == 2:
                    pcap_name, max_mode = tokens
                    min_mode = modes[0]
                    if max_mode == "MAX": max_mode = modes[-1]
                    if min_mode not in modes or max_mode not in modes:
                        print("invalid line in " + args.modes + ":\n" + line)
                        exit(1)
                    modes_file_map[pcap_name] = (min_mode, max_mode)
                elif len(tokens) == 0:
                    pass
                else:
                    print("invalid line in " + args.modes + ":\n" + line)
                    exit(1)

    default_mode = args.dmode
    if default_mode == "MIN": default_mode = modes[0]
    if default_mode == "MAX": default_mode = modes[-1]
    pcap_modes = dict()
    for pcap_path in pcap_paths:
        pcap_name = os.path.basename(pcap_path)
        if pcap_name in modes_file_map:
            min_mode, max_mode = modes_file_map[pcap_name]
            if modes.index(default_mode) < modes.index(min_mode):
                pcap_modes[pcap_path] = min_mode
            elif modes.index(default_mode) > modes.index(max_mode):
                pcap_modes[pcap_path] = max_mode
            else:
                pcap_modes[pcap_path] = default_mode
        else:
            pcap_modes[pcap_path] = default_mode

    ip_maps = dict() # (pcap, iteration) -> ip_map

    for x in range(args.iterations):
        for pcap_path in pcap_paths:
            hosts, host_pairs = parse_pcap(pcap_path)
            if len(hosts) == 0:
                # TODO: set mode to L2 for these
                print("[!]\tNo IP or IPv6 hosts found for " + pcap_path)
                # fake to results & ip_map
                fake_cmd_args = ("-p", pcap_path, x)  # iteration number ("x") to make key unique
                results[fake_cmd_args] = REPLAY_NOT
                ip_maps_key = (pcap_path, x)
                ip_maps[ip_maps_key] = {}
                continue
            partitions = distribute_nodes(len(nics), hosts, host_pairs)
            ip_map = {}
            replayed_address_nic_map = {}  # replayed -> nic["name"] mapping
            is_ipv4 = "." in next(iter(hosts))  # can only do all IPv4 or all IPv6 pcaps
            for original_address in hosts:
                index = None
                for i in range(len(partitions)):
                    if original_address in partitions[i]:
                        index = i
                nic = nics[index]
                while True:
                    random_address = random_ipv4_address(nic["subnet"]) if is_ipv4 else random_ipv6_address(
                        nic["subnet_v6"], b"" if args.randomip6 else nic["last_bytes_v6"])
                    if random_address in consumed_addresses:
                        continue
                    else:
                        ip_map[original_address] = random_address
                        replayed_address_nic_map[random_address] = nic["name"]
                        consumed_addresses.add(random_address)
                        break

            cmdline = [bin_path, ] + args.packetator_args
            mode = pcap_modes[pcap_path]
            mode_config = mode + ".yaml"
            mode_config = os.path.abspath(os.path.join(os.path.dirname(bin_path), mode_config))
            cmdline += ["-c", mode_config]
            cmdline += ["-p", pcap_path]
            for original_address, replayed_address in ip_map.items():
                cmdline += ["-m", original_address + "=" + replayed_address]

            for nic in nics:
                cmdline += ["-i", nic["name"], "-s", nic["subnet"] if is_ipv4 else nic["subnet_v6"]]
                if nic.get("gateway" if is_ipv4 else "gateway_v6", ""):
                    cmdline += ["-g", nic["gateway" if is_ipv4 else "gateway_v6"]]

            for original_address, replayed_address in ip_map.items():
                cmdline += ["-a", replayed_address + "," + replayed_address_nic_map[replayed_address] + (
                    "," + generate_mac(oui="00") if args.randommac else "")]

            cmdlines.append(cmdline)
            ip_maps_key = (pcap_path, x)
            ip_maps[ip_maps_key] = ip_map

    pcap_iteration_counts = dict()
    arguments_list = []
    for cmdline in cmdlines:
        pcap_path_index = None
        for i in range(len(cmdline)):
            if cmdline[i] == "-p":
                pcap_path_index = i + 1
                break
        pcap_filepath = cmdline[pcap_path_index]
        if pcap_filepath not in pcap_iteration_counts:
            pcap_iteration_counts[pcap_filepath] = 0
        pcap_iteration_counts[pcap_filepath] = pcap_iteration_counts[pcap_filepath] + 1
        iteration_count = pcap_iteration_counts[pcap_filepath]
        meta = dict()
        meta["iteration_count"] = iteration_count
        arguments = (cmdline, meta)
        arguments_list.append(arguments)

    print("[+]\tReplaying pcaps...")
    r = list(tqdm.tqdm(pool.imap_unordered(run_packetator, arguments_list), total=len(arguments_list)))

    iteration_results = dict()

    for result in results:
        cmd = result
        cmd_args = cmd
        pcap_path_index = None
        for i in range(len(cmd_args)):
            if cmd_args[i] == "-p":
                pcap_path_index = i + 1
                break
        pcap_filepath = cmd_args[pcap_path_index]

        # error codes that will require environment changes to fix
        if results[cmd] == "error (2)":
            print("[!]\tError: Message too long (MTU too small ?) for " + pcap_filepath)
        if results[cmd] == "error (3)":
            print("[!]\tError: No packets to replay for " + pcap_filepath)
        if results[cmd] == "error (1001)":
            print("[!]\tError: Process timed out " + pcap_filepath)

        if pcap_filepath not in iteration_results:
            iteration_results[pcap_filepath] = []

        iteration_results[pcap_filepath].append(results[cmd])


    results_output = []

    for pcap_filepath in iteration_results:
        success_count = 0
        for result in iteration_results[pcap_filepath]:
            if result == REPLAY_SUCCESS:
                success_count += 1
        not_replayed = False
        if success_count == 0:
            for result in iteration_results[pcap_filepath]:
                not_replayed = result == REPLAY_NOT

        # pcap basename, mode, success count, number of iterations, overall result, result 1, result 2, ..., ip addresses 1, ip addresses 2, ...
        result_output = [os.path.basename(pcap_filepath),
                         pcap_modes[pcap_filepath],
                         success_count,
                         args.iterations,
                         (REPLAY_SUCCESS if success_count > 0 else (REPLAY_NOT if not_replayed else REPLAY_FAILURE))]
        for i in range(len(iteration_results[pcap_filepath])):
            result = iteration_results[pcap_filepath][i]
            result_output.append(result)
        for i in range(len(iteration_results[pcap_filepath])):
            ip_maps_key = (pcap_filepath, i)
            ip_map = ip_maps[ip_maps_key]
            ip_map_items = sorted(ip_map.items(), key=lambda item: socket.inet_pton(socket.AF_INET if "." in item[0] else socket.AF_INET6, item[0])) # sort addresses by ascending order of the original ip addresses
            ip_addresses = [item[1] for item in ip_map_items]
            result_output.append(" ".join(ip_addresses))
        results_output.append(result_output)

    if args.outfile:
        with open(os.path.expanduser(args.outfile), "w") as f:
            for result_output in results_output:
                f.write(",".join(str(x) for x in result_output) + "\n")

    if args.zipdir:
        print("[+]\tCompressing pcaps...")
        try:
            os.mkdir(args.zipdir)
        except:
            pass
        p_filepaths_dict = {}
        for pcap_filepath in iteration_results:
            pcap_basename = os.path.basename(pcap_filepath)
            p_filepaths = []
            for i in range(len(iteration_results[pcap_filepath])):
                ip_maps_key = (pcap_filepath, i)
                ip_map = ip_maps[ip_maps_key]
                for k, v in ip_map.items():
                    p_filename = "{}_{}.pcap".format(k, v)
                    p_filepath = os.path.join(args.outdir, pcap_basename, str(i+1), p_filename)
                    p_filepaths.append(p_filepath)
            if p_filepaths:
                p_filepaths_dict[pcap_basename] = p_filepaths

        def zip_files(args):
            zip_filename, filepaths, compresslevel = args
            if filepaths:
                compression = zipfile.ZIP_DEFLATED
                zf = zipfile.ZipFile(zip_filename, mode="w", compresslevel=compresslevel)
                try:
                    for filepath in filepaths:
                        zf.write(filepath, os.path.basename(filepath), compress_type=compression, compresslevel=compresslevel)
                except FileNotFoundError:
                    pass
                finally:
                    zf.close()
        zip_files_arguments_list = [(os.path.join(args.zipdir, "{}.zip".format(k)), p_filepaths_dict[k], 9) for k in p_filepaths_dict]
        zip_pool = ThreadPool(processes=multiprocessing.cpu_count()+1)
        r = list(tqdm.tqdm(zip_pool.imap_unordered(zip_files, zip_files_arguments_list), total=len(p_filepaths_dict)))

    # count summary
    success_count = 0
    failure_count = 0
    not_count = 0
    for result_output in results_output:
        overall_result = result_output[4]
        if overall_result == REPLAY_SUCCESS:
            success_count += 1
        elif overall_result == REPLAY_FAILURE:
            failure_count += 1
        elif overall_result == REPLAY_NOT:
            not_count += 1
    total_count = success_count + failure_count + not_count

    rjust = max(len(REPLAY_SUCCESS), len(REPLAY_FAILURE), len(REPLAY_NOT))
    print("="*10 + " Result Count Summary " + "="*10)
    print("\t{}: {}/{}".format(REPLAY_SUCCESS.rjust(rjust), success_count, total_count))
    print("\t{}: {}/{}".format(REPLAY_FAILURE.rjust(rjust), failure_count, total_count))
    print("\t{}: {}/{}".format(REPLAY_NOT.rjust(rjust), not_count, total_count))
