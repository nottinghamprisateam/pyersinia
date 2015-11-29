# -*- coding: utf-8 -*-

"""
This file contains API calls and Data
"""

import six
from sys import version_info
from termcolor import colored
from .data import *
from os import geteuid

__version__ = "1.0.0"
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
    six.print_(colored("[*]", "blue"), "Done!")


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

    if geteuid():
        six.print_(colored("[!]", "red"), "DENIED! Please run as root.")
        exit()

    # --------------------------------------------------------------------------
    #
    # --------------------------------------------------------------------------

    # ARP attack import
    if config.attack == ['arp_spoof']:
        from .libs.plugins.arp_poison import run_attack

    # Dhcp_discover_dos attack import
    elif config.attack == ['dhcp_discover_dos']:
        from .libs.plugins.dhcp_discover_dos import run_attack
        six.print_(colored("[*]", "blue"), "Running DHCP DISCOVER ATTACK...")

    # Stp_tcn attack import
    elif config.attack == ['stp_tcn']:
        from .libs.plugins.stp_tcn import run_attack
        six.print_(colored("[*]", "blue"), "Running STP TCN ATTACK...")

    # Stp_conf attack import
    elif config.attack == ['stp_conf']:
        from .libs.plugins.stp_bdpu_conf import run_attack
        six.print_(colored("[*]", "blue"), "Running STP CONF ATTACK...")

    # New attack import
    # ...
    # ...

    else:
        print "Attack does not exist!"
        exit()

    run_attack(config)

