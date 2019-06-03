#!/usr/bin/python3
import os
import logging
import subprocess
import sys
import xml.etree.ElementTree as eT
from argparse import ArgumentParser
import netifaces as ni


#### SHORT SUMMARY ######################################################################
# In this script we take arguments over ArgumentParser module and store them,
# start an nmap scan according to the arguments,
# add information about used interface (addr., broadcast, gateway, netmask)
# and add targets of scan to the xml.
# The xml can be imported by calling `reporting seg <file>` into your segmentation report.
# This also works for multiple scans/xml files.
# Shoutout to Felix for the weird code I had to fix
#     - Aron
##########################################################################################

def is_create_file_valid(f):
    """ Check if path exists and we have write access in it. """
    if (not os.path.exists(f)) and os.access('.', os.W_OK):
        return True
    LOGGER.error("[!!] Fatal error: No local write access.")
    sys.exit(-1)

def file_readable(path):
    """ Returns True if file exists and is readable. """
    return os.path.isfile(path) and os.access(path, os.R_OK)


def file_rwable(f):
    """ Returns True if file exist and is either readable and writable"""

    return os.path.isfile(f) and os.access(f, os.R_OK & os.W_OK)


def check_ip(ip):
    """ Returns True if the provided string is a IPV4 address. """
    ipv4check = lambda xs: xs.count('.') == 3 and all(
        len(x) <= 3 and 0 <= int(x) <= 255 for x in xs.split('.'))
    return ipv4check(ip)



def check_cidr_notation(subns):
    """ Returns True if the provided string is a subnet address in CIDR notation. """

    ipv4split = subns.rstrip().split('/')
    return subns.count('/') == 1 and check_ip(ipv4split[0]) and 0 <= int(ipv4split[1]) <= 32



def check_port_format(args):
    """
    Check, if arg is a valid port notation.
    If arg is neither a valid port number, X-Y or X,Y,Z the range is invalid.
    """

    portrngch = lambda xs: (xs.count('-') == 1) and all(0 <= int(x) <= 65535 for x in xs.split('-'))
    portnumch = lambda xs: all(0 <= int(x) <= 65535 for x in xs.split(','))
    if not (portrngch(args) or portnumch(args)):
        LOGGER.error("[!] Invalid portrange.")
        return False
    return True


def write_info(interface, targets, nmapfile):
    """
    Gather interface data and write into generated xml

    Arguments:
        interface {string} -- The interface argumt from call
        targets {string} -- The target argument from call
        nmapfile {string} -- Filename of generated XML file
    """

    getit = lambda xs: list(x for k, v in ni.ifaddresses(xs).items() for x in v)
    netinfo = getit(interface)[1]
    netinfo['gateway'] = ni.gateways()['default'][ni.AF_INeT][0]
    tree = eT.parse(nmapfile)
    root = tree.getroot()
    root.set("target", targets)
    ifaceinfo = eT.Element("ifaceinfo")
    ifaceinfo.set("addr", netinfo["addr"])
    ifaceinfo.set("gateway", netinfo["gateway"])
    ifaceinfo.set("netmask", netinfo["netmask"])
    ifaceinfo.set("broadcast", netinfo["broadcast"])
    root.insert(1, ifaceinfo)
    tree.write(nmapfile)


def validate_xml(filename_xml):
    """ Return validity of xml. """

    with open(filename_xml, 'r') as xml_file:
        xml_to_check = xml_file.read()
    try:
        eT.fromstring(xml_to_check)
    # check for file IO error
    except IOError as e:
        LOGGER.warning("[!] XML not readable: %s", e)
        return False
    except eT.ParseError as e:
        LOGGER.warning("[!] Malformed XML: %s", e)
        return False
    return True

def parse_nmap_xml():
    """ Deprecated, moved to reporting tool. """
    return -1

def start_nmap_scans(args):
    """
    Start nmap an return string containing path of result xml.
    Arguments from segmentationtest.py call are passed to define nmap command
    and the filename.

    """
    if args.o:
        nmapfile = args.o
    else:
        # Target is single IP or in CIDR notation
        if check_ip(args.s) or check_cidr_notation(args.s):
            nmapfile = "nmap_{}.xml".format(args.s)
        # Target is in unknown format, warn user and create filename
        else:
            nmapfile = "nmap_{}.{}.{}.X.xml"
            nmapfile.format(args.s.split('.')[0], args.s.split('.')[1], args.s.split('.')[2])
            LOGGER.warning("[!] Unidentified target, using %s as filename.", nmapfile)

    command = None
    # If we don't rescan and there is a file: if valid xml exit, else continue scan
    if (not args.rescan) and file_readable(nmapfile):
        if validate_xml(nmapfile):
            LOGGER.error("[!] This target is already completely scanned.")
            sys.exit()
        else:
            LOGGER.warning("[!] Current  XML ist not valid. Continuing scan...")
            if file_rwable(nmapfile):
                command = "nmap --resume "+nmapfile

    if command is None:
        command = "nmap {} -Pn --disable-arp-ping --version-light -n -oX {} -T{} -p {} " \
                    "--max-retries={} --max-scan-delay={}ms --max-rtt-timeout={}ms " \
                    "--min-rate={} --min-hostgroup={} -v"
        command = command.format(args.s, nmapfile, args.t, args.p, args.max_tries,
                                 args.max_scan_rate, args.max_rtt, args.min_rate,
                                 args.min_hostgroup)

        if args.sS:
            command += " -sS"
        if args.sT:
            command += " -sT"

    LOGGER.info("[*] Starting scan of %s", args.s)
    proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
    try:
        proc.communicate()
    except OSError as e:
        LOGGER.error("[!!] Exiting due to fatal subprocess error: %s", e)
        sys.exit(-1)
    write_info(args.interface, args.s, nmapfile)
    return nmapfile

def cli_parser(args):
    """Parse call arguments and store them in a parser Object. """
    LOGGER.debug("[*] Starting CLI Parser")
    parser = ArgumentParser()
    parser.add_argument("-i", "--interface",
                        dest="interface",
                        type=str, default="eth0",
                        help="Interface name.")
    parser.add_argument("-s", type=(lambda x: x),
                        required=True,
                        help="Targets for scan. Look into nmap documentation for notation help.")
    parser.add_argument("-t", type=int, default=4, help="nmap scan level")
    parser.add_argument("-p",
                        type=(lambda x: x if check_port_format(x) else None),
                        default="1-65535", help="ports range to scan e.g, 1-65535  or 22,23,443")
    parser.add_argument("-sS", action="store_const", const="sS",
                        help="SYN SCAN, default is off")
    parser.add_argument("-sT", action="store_const", const="sT",
                        help="TCP Connect() , default is off")
    parser.add_argument("--max_tries", type=int, default=2, help="Max tries")
    parser.add_argument("--max_scan_rate", type=int, default=100,
                        help="Max scan rate in ms")
    parser.add_argument("--max_rtt", type=int, default=150, help="max rtt timeout")
    parser.add_argument("--min_rate", type=int, default=80, help="min rate in ms")
    parser.add_argument("--min_hostgroup", type=int, default=1,
                        help="host scan size for parallel scans")
    parser.add_argument("-o", "--output",
                        type=(lambda x: x if is_create_file_valid(x) else None),
                        metavar="FILE", help="Output file")
    parser.add_argument("-q", "--quiet", action="store_false",
                        help="Active silent mode, default is false")
    parser.add_argument("--rescan", "-r", action="store_true",
                        help="Rescan already scanned target.")
    segtest = parser.parse_args(args)
    if segtest.sS:
        if os.getenv("SUDO_USER") is None:
            LOGGER.warning("[!] Missing privileged access for TCP SYN Scan, using TCP Connect.")
            segtest.sS = None
    return segtest

def merge_files():
    """ Deprecated, no need to merge since nmaps xml output covers all results. """
    return -1

if __name__ == '__main__':
    logging.basicConfig(level=logging.WARNING, format='%(levelname)s: %(message)s')
    LOGGER = logging.getLogger(__name__)
    start_nmap_scans(cli_parser(sys.argv[1:]))
