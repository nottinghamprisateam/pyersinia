# -*- coding: utf-8 -*-

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import argparse

log = logging.getLogger(__name__)


# ----------------------------------------------------------------------
def main():

    from .api import run_console, GlobalParameters

    examples = '''
example for each attack:
        python %(tool_name)s.py -a arp_spoof 127.0.0.1 127.0.0.1
        python %(tool_name)s.py -a dhcp_discover_dos -i eth0
        python %(tool_name)s.py -a stp_tcn -i lo
    '''  % dict(tool_name="pyersinia")

    parser = argparse.ArgumentParser(description='#############################\n'
                                                 '####%s attack tool####\n'
                                                 '#############################' % "pyersinia".capitalize(),
                                     epilog=examples, formatter_class=argparse.RawTextHelpFormatter)

    # Main options
    parser.add_argument("-v", "--verbosity", dest="verbose", action="count",
                        help="verbosity level", default=0)

    parser.add_argument("-a", "--attack", required=True, help="choose attack type",
                        nargs=1, dest="attack")

    parser.add_argument("-i", "--iface", dest="interface", required=True, help="choose interface", nargs=1,
                        metavar="iface")

    # Arp_Spoof args
    parser.add_argument("target", metavar="arp_spoof_TARGET", nargs="?")
    parser.add_argument("victim", metavar="arp_spoof_VICTIM", nargs="?")

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
        log.info("[!] Unhandled exception: %s" % str(e))

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


