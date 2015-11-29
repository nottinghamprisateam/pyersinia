import logging
logging.getLogger("scapy.runtime").setLevel(logging.WARNING)

from scapy.layers.l2 import LLC, STP, Dot3
from scapy.all import sendp,sniff



def run(interface):
    pkt = sniff(stop_filter=lambda x: x.haslayer(STP), iface=interface)


def run_attack(config):
    run(config.interface)