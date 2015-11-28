# -*- coding: utf-8 -*-

import argparse
import logging

log = logging.getLogger(__name__)


# ----------------------------------------------------------------------
def main():

    from .api import run_console, GlobalParameters

    examples = '''
Examples:

        %(tool_name)s --attack arp x.x.x.x y.y.y.y
        %(tool_name)s --attack dhcp_discover_dos -i eth0
    '''  % dict(tool_name="pyersinia")

    parser = argparse.ArgumentParser(description='%s security tool' % "pyersinia".capitalize(), epilog=examples,
                                     formatter_class=argparse.RawTextHelpFormatter)

    # Main options

    parser.add_argument("-v", "--verbosity", dest="verbose", action="count",
                        help="verbosity level: -v, -vv, -vvv.", default=0)

    parser.add_argument("--attack", required=True, help="start attack arp posion",
                        nargs=1, dest="attack", metavar="ATTACK")

    # Arp Spoof
    parser.add_argument("target", metavar="TARGET", nargs="?")
    parser.add_argument("victim", metavar="VICTIM", nargs="?")

    # dhcp_Discover
    parser.add_argument("-i", dest="interface", nargs=1, metavar="INTERFACE")


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
    if sys.version_info < 3:
        print("\n[!] You need a Python version greater than 3.x\n")
        exit(1)

    del sys, os

    main()


