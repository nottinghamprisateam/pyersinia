# -*- coding: utf-8 -*-

"""
This file contains API calls and data
"""

import six
from sys import version_info
from termcolor import colored
from .data import *
from os import geteuid
import netifaces

__version__ = "1.0.4"
__all__ = ["run_console", "run", "GlobalParameters"]


# --------------------------------------------------------------------------
#
# Command line options
#
# --------------------------------------------------------------------------
def run_console(config):
    """
    :param config: GlobalParameters option instance
    :type config: `GlobalParameters`

    :raises: TypeError
    """
    if not isinstance(config, GlobalParameters):
        raise TypeError("Expected GlobalParameters, got '%s' instead" % type(config))

    six.print_(colored("[*]", "blue"), "Starting Pyersinia execution -->")
    run(config)
    six.print_(colored("\n[*]", "yellow"), "Attack stopped. ")


# ----------------------------------------------------------------------
#
# API call
#
# ----------------------------------------------------------------------
def run(config):
    """
    :param config: GlobalParameters option instance
    :type config: `GlobalParameters`

    :raises: TypeError
    """
    if not isinstance(config, GlobalParameters):
        raise TypeError("Expected GlobalParameters, got '%s' instead" % type(config))

    # --------------------------------------------------------------------------
    # Evaluate the type of attack and the interface to be launched
    # --------------------------------------------------------------------------
    if geteuid():
        six.print_(colored("[!]", "red"), "DENIED! Please run as root.")
        exit()

    # --------------------------------------------------------------------------
    # Evaluate the type of attack and the interface to be launched
    # --------------------------------------------------------------------------
    ifaceList = netifaces.interfaces()      # List of interfaces
    if config.interface[0] in ifaceList:

        # ARP attack import
        if config.attack == ['arp_spoof']:
            evalueAddr(config.target, config.victim)
            from .libs.plugins.arp_poison import run_attack
            six.print_(colored("[*]", "blue"), "Running ARP SPOOF ATTACK...")

        # Dhcp_discover_dos attack import
        elif config.attack == ['dhcp_discover_dos']:
            from .libs.plugins.dhcp_discover_dos import run_attack
            six.print_(colored("[*]", "blue"), "Running DHCP DISCOVER DoS ATTACK...")

        # Stp_tcn attack import
        elif config.attack == ['stp_tcn']:
            from .libs.plugins.stp_tcn import run_attack
            six.print_(colored("[*]", "blue"), "Running STP TCN ATTACK...")

        # Stp_conf attack import
        elif config.attack == ['stp_conf']:
            from .libs.plugins.stp_bdpu_conf import run_attack
            six.print_(colored("[*]", "blue"), "Running STP CONF ATTACK...")
        # Stp_root attack import
        elif config.attack == ['stp_root']:
            from .libs.plugins.stp_root_role import run_attack
            six.print_(colored("[*]", "blue"), "Running STP ROOT ROLE ATTACK...")

        # New attack import
        # ...
        # ...

        else:
            six.print_(colored("[!]", "red"), "ERROR! Attack does not exist.")
            exit()

    else:
        six.print_(colored("[!]", "red"), "ERROR! You are not connected to require interface.")
        exit()

    # Run attack chosen
    run_attack(config)


def evalueAddr(target, victim):
    min = 0
    max = 255
    count = 0
    fields = 8

    for x in target.split('.'):
        if int(x) >= min and int(x) <= max:
            count += 1

    for x in victim.split('.'):
        if int(x) >= min and int(x) <= max:
            count += 1

    if count != fields:
        six.print_(colored("[!]", "red"), "ERROR! Invalid IPs.")
        exit()
