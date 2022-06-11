#!/usr/bin/python3

from termcolor import colored
from argparse import ArgumentParser

from XSSTerminal.lib.Engine import XSST
from XSSTerminal.lib.Globals import Color
from XSSTerminal.lib.Functions import starter, exit_handler

def main():
    parser = ArgumentParser(description=colored("XSS Terminal", color='yellow'),
            epilog=colored('<script>window.location="https://bit.ly/3n60FQ4";</script>', color='yellow'))
    parser.add_argument('-u', '--url', type=str, help="URL with custom payload")
    string_group = parser.add_mutually_exclusive_group()
    string_group.add_argument('-e', '--error-string', type=str, help="Error string")
    string_group.add_argument('-s', '--match-string', type=str, help="Match string")
    string_group.add_argument('-b', '--blind-string', type=str, help="Blind error string")
    parser.add_argument('-m', '--method', type=str, choices=['GET','POST'], help="HTTP Method")
    parser.add_argument('-o', '--output', type=str, help="Output file name")
    parser.add_argument('-r', '--resume', type=str, help="Filename to resume XSST session")
    parser.add_argument('--readline', action="store_true", help="Use readline for input")
    parser.add_argument('--banner', action="store_true", help="Print banner and exit")
    argv = parser.parse_args()

    xurl, xsstinput = starter(argv)
    terminal = XSST(xurl, xsstinput)

    while True:
        try:
            terminal.make_xss(argv)
        except KeyboardInterrupt:
            exit_handler(terminal.base_url, terminal.xss_payload, filename=argv.output)
            exit()
        except Exception as E:
            from traceback import print_exc
            print_exc()
