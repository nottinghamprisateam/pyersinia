# -*- coding: utf-8 -*-

import six
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *
import argparse

logging.basicConfig(format="%(message)s")
log = logging.getLogger(__name__)


# ----------------------------------------------------------------------
def discover_plugins():
    """
    This function try to discover installed plugins dinamically

    :return: a list with plugins names
    :rtype: list(str)

    """
    from os import listdir
    from os.path import join, abspath, dirname

    path = join(abspath(dirname(__file__)), "libs", "plugins")

    plugin_list = []

    for f in listdir(path):
        if not f.startswith("__") and f.endswith(".py"):
            plugin_list.append(f.replace(".py", ""))

    return plugin_list


# ----------------------------------------------------------------------
def main():

    # Get available plugins
    plugins = discover_plugins()

    try:
        from .api import run_console, GlobalParameters
    except ImportError as e:
        six.print_("\n[!] You need to install dependency: '%s'\n" % str(e).replace("No module named ", ""))

        six.print_("To install missing dependencies doing: \n")
        six.print_("# pip install scapy termcolor netifaces pcapy dnet\n")
        exit(1)

    examples = '''
supported attacks:
        %(attacks)s

examples:
        python %(tool_name)s.py -a arp_spoof 127.0.0.1 127.0.0.1
        python %(tool_name)s.py -a stp_root -i eth0
    ''' % dict(tool_name="pyersinia", attacks=", ".join(plugins))

    parser = argparse.ArgumentParser(description='#############################\n'
                                                 '####%s attack tool####\n'
                                                 '#############################' % "pyersinia".capitalize(),
                                     epilog=examples, formatter_class=argparse.RawTextHelpFormatter)

    # Main options
    parser.add_argument("-v", "--verbosity", dest="verbose", action="count",
                        help="verbosity level", default=0)

    parser.add_argument("-a", required=True, help="choose supported attack type",
                        nargs=1, dest="attack", metavar="ATTACK_TYPE", choices=plugins)

    parser.add_argument("-i", dest="interface", required=True, help="choose network interface", nargs=1,
                        metavar="IFACE")

    # Arp_Spoof args
    parser.add_argument("target", metavar="arp_spoof_TARGET", nargs="?")
    parser.add_argument("victim", metavar="arp_spoof_VICTIM", nargs="?")

    # DHCP Rogue

    parser.add_argument("-g", dest="gateway", help="gateway ip for DHCP conf")
    parser.add_argument("-s", dest="ipserver", help="DHCP ip server")
    parser.add_argument("-n", dest="network", help="network address. Example: 192.168.1.0")
    parser.add_argument("-m", dest="netmask", help="netmask. Example: 255.255.255.0")
    parser.add_argument("--domain", dest="domain", help="domain name")
    parser.add_argument("--sdomain", dest="server_domain", help="ip address of name server domain")

    #PoC XSS
    parser.add_argument("--xss", dest="xss", help="xss <script>alert('hola')</script>")
    parsed_args = parser.parse_args()

    # Configure global log
    log.setLevel(abs(5 - parsed_args.verbose) % 5)

    # Set Global Config
    config = GlobalParameters(parsed_args)

    try:
        run_console(config)
    except KeyboardInterrupt:
        log.warning("[*] CTRL+C caught. Exiting...")
    except Exception as e:
        log.critical("[!] Unhandled exception: %s" % str(e))

if __name__ == "__main__" and __package__ is None:
    # --------------------------------------------------------------------------
    #
    # INTERNAL USE: DO NOT MODIFY THIS SECTION!!!!!
    #
    # --------------------------------------------------------------------------
    import sys
    import os
    parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sys.path.insert(1, parent_dir)
    import pyersinia_lib
    __package__ = str("pyersinia_lib")
    # Checks Python version
    #if sys.version_info < 3:
    #    print("\n[!] You need a Python version greater than 3.x\n")
    #    exit(1)

    del sys, os

    main()


