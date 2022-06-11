#!/usr/bin/python3
import urllib.parse
import readline

from requests import Session
from termcolor import colored
from os import system
from argparse import ArgumentParser

from lib.Globals import *
from lib.Functions import starter, exit_handler

s = Session()

parser = ArgumentParser(description=colored("XSS Terminal", color='yellow'), epilog=colored('<svg onload=alert(1)></svg>', color='yellow'))
parser.add_argument('-u', '--base-url', type=str, help="Base URL")
parser.add_argument('-p', '--payload', type=str, help="Starting payload")
parser.add_argument('-e', '--error-string', type=str, help="Error string (Leave empty for -p check)")
parser.add_argument('-s', '--match-string', type=str, help="Match string from payload (for false WAF Triggers)")
parser.add_argument('-o', '--output', type=str, help="Output file name")
parser.add_argument('-r', '--resume', type=str, help="Filename to resume XSST session")
parser.add_argument('-b', '--banner', action="store_true", help="Print banner and exit")
argv = parser.parse_args()

xss_base, xss_payload = starter(argv)

class XSST:
    def __init__(self, base, xss_payload):
        self.payload = ""
        self.base_url = base 
        self.xss_payload = xss_payload
        system('clear')

    def xss_input(self, prompt, text):
        def hook():
            readline.insert_text(text)
            readline.redisplay()
        readline.set_pre_input_hook(hook)
        result = input(prompt)
        readline.set_pre_input_hook()
        return result

    def return_xsscolor(self, xss, joinable) -> str:
        xssz = urllib.parse.unquote_plus(urllib.parse.unquote_plus(xss)).rstrip(' ')
        if len(joinable) > 1:
            if not "".join(joinable[1:]) in xssz:
                xss_payload = joinable[0] + colored(xssz, color='red') + "".join(joinable[1:])
        elif len(joinable) == 1:
            if not xssz in joinable[0]:
                xss_payload = joinable[0] + colored(xssz, color='red')
            else:
                xss_payload = joinable[0].split(xssz)[0] + colored(xssz, color='red')
        return xss_payload

    def stringxss_check(self, xss_list) -> str:
        if argv.match_string:
            for xssy in xss_list:
                if urllib.parse.unquote_plus(urllib.parse.unquote_plus(argv.match_string)) in urllib.parse.unquote_plus(xssy):
                    return xssy
        else:
            for xssy in xss_list:
                if urllib.parse.unquote_plus(urllib.parse.unquote_plus(self.xss_payload)) in urllib.parse.unquote_plus(xssy):
                    return xssy
        return 'WAF Triggered'

    def errorxss_check(self, xss_list) -> str:
        for xssy in xss_list:
            xssz = urllib.parse.unquote_plus(xssy)
            if not urllib.parse.unquote_plus(argv.error_string) in xssz:
                if urllib.parse.unquote_plus(urllib.parse.unquote_plus(self.xss_payload)) in xssz:
                    return xssy
            if urllib.parse.unquote_plus(argv.error_string) in xssz:
                return 'WAF Triggered'
        return 'WAF Triggered'

    def make_xss(self):
        try:
            self.xss_payload = self.xss_input(f"{ColorObj.information} XSS Payload :> ", self.xss_payload)
            url = self.base_url + self.xss_payload
            response = s.get(url).text
            xss_list = response.split('\n')
            if argv.error_string:
                xssy = self.errorxss_check(xss_list)
            elif argv.payload:
                xssy = self.stringxss_check(xss_list)
        except Exception as E:
            print(E)
        if not xssy == 'WAF Triggered':
            colorful_xss = self.return_xsscolor(self.xss_payload, [xssx for xssx in xssy.strip().split(self.xss_payload) if xssx])
            print(f"{ColorObj.good} {colorful_xss}")
        if xssy == 'WAF Triggered':
            print(f"{ColorObj.bad} {xssy}")
    
if __name__ == "__main__":
    Terminal = XSST(xss_base, xss_payload)
    while True:
        try:
            Terminal.make_xss()
        except KeyboardInterrupt:
            if not argv.output:
                exit_handler(Terminal.base_url, Terminal.xss_payload)
            else:
                exit_handler(Terminal.base_url, Terminal.xss_payload, filename=argv.output)
        except Exception as E:
            print(E.__class__)
            print(E)
            print("WHAT")
            exit()
