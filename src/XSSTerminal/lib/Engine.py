import re
from os import system
from requests import Session
from random import choice
from string import ascii_lowercase, digits
from bs4 import BeautifulSoup
from termcolor import colored
from urllib.parse import unquote_plus as urldecode
from urllib.parse import ParseResult, urlparse, urlunparse

from XSSTerminal.lib.Globals import Color
from XSSTerminal.lib.PathFunctions import urler

class XSST:
    def __init__(self, url, input_type):
        self.s = Session()
        base, payload_param = self.xss_urlparse(url)
        rnstring = lambda n: "".join((choice(ascii_lowercase + digits) for x in range(n)))
        if not "&" in payload_param:
            param, payload = payload_param.split('=')[0], payload_param.split('=')[1]
        self.base_url = f"{base}&{param}="
        self.xss_payload = rnstring(2) + payload + rnstring(2)
        self.xss_input = input_type
        system('clear')

    def xss_urlparse(self, url):
        url = urler(url)
        parsed_url = urlparse(url)
        scheme, netloc, path, params, query, fragment = parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, parsed_url.query, parsed_url.fragment
        unxss_tuple, xss_tuple = self.xss_query(query)
        query = unxss_query = "&".join(["=".join(pv) for pv in unxss_tuple])
        xss_query ="&".join(["=".join(pv) for pv in xss_tuple])
        xss_base = urlunparse(ParseResult(scheme = scheme, netloc = netloc, path = path, params = params, query = query, fragment = fragment))
        return xss_base, xss_query

    def xss_query(self, query):
        if not query:
            return query
        matches = ("<script", "alert(")
        found = re.findall(r'([^&]+)=([^&]+)', query)
        match_tuple = []
        for param, value in found:
            #if param == argv.param:
            #    match.append((param, value))
            for match in matches:
                if match in value:
                    match_tuple.append((param, value))
        xss_tuple = list(set(found) - set(match))
        return xss_tuple, match_tuple

    def return_xsscolor(self, xss_payload, joinable) -> str:
        xssz = urldecode(urldecode(xss_payload)).rstrip(' ')
        if len(joinable) > 1:
            if not "".join(joinable[1:]) in xssz:
                xss_payload = joinable[0] + colored(xssz, color='red') + "".join(joinable[1:])
        elif len(joinable) == 1:
            if not xssz in joinable[0]:
                xss_payload = joinable[0] + colored(xssz, color='red')
            else:
                xss_payload = joinable[0].split(xssz)[0] + colored(xssz, color='red')
        return xss_payload
    #colorful_xss = self.return_xsscolor(self.xss_payload, [xssx for xssx in xssy.strip().split(self.xss_payload) if xssx])

    def color_xss(self, xssy):
        match, line = xssy
        xss_payload = urldecode(match)
        if xss_payload == line:
            final = colored(xss_payload, color='red', attrs=['bold'])
        elif match in line:
            first, last = line.split(xss_payload, 1)
            middle = colored(xss_payload, color='red', attrs=['bold'])
            if match in last:
                first = first + middle
                last_first, last_last = last.split(xss_payload, 1)
                final = first + last_first + colored(xss_payload, color='red', attrs=['bold']) + last_last
            else:
                final = first + xss_payload + last
        return final

    def xss_reflection_check(self, xss_list, xss_strings) -> str:
        match_string = error_string = ""
        if xss_strings['match_string']:
            match_string = urldecode(urldecode(xss_strings['match_string']))
        if xss_strings['error_string']:
            error_string = urldecode(urldecode(xss_strings['error_string']))
        xss_payload = urldecode(urldecode(self.xss_payload))
        reflections = {
            'xss_matches': [],
            'waf_matches': [],
        }
        for xss_line in xss_list.split('\n'):
            xss_line = urldecode(xss_line)
            if match_string:
                if match_string in xss_line:
                    for xssp in re.findall(match_string, xss_line):
                        reflections['xss_matches'].append((match_string, xss_line))
            elif error_string:
                if error_string in xss_line:
                    reflections['waf_matches'].append("WAF Triggered")
            else:
                if xss_payload in xss_line:
                    for xssp in re.findall(xss_payload, xss_line):
                        reflections['xss_matches'].append((xssp, xss_line))
        return reflections

    # def blindxss_check(self, xss_list, blind_string=None) -> str:
        # for xss_line in xss_list:
            # xssz = urldecode(xss_line)
            # if urllib.parse.unquote(blind_string) in xssz:
                # return 'WAF Triggered'
    #     return 'Blind'

    def make_xss(self, argv):
        xstrings = {
            'match_string': argv.match_string,
            'error_string': argv.error_string,
            'blind_string': argv.blind_string,
        }
        try:
            self.xss_payload = self.xss_input(f"{Color.information} XSS Payload :> ", self.xss_payload)
            url = self.base_url + self.xss_payload
            source_code = self.s.get(url).text
            xssi = self.xss_reflection_check(source_code, xstrings)
        except Exception as E:
            from traceback import print_exc
            print_exc()

        if xssi['xss_matches']:
            for xssy in xssi['xss_matches']:
                #colorful_xss = self.return_xsscolor(self.xss_payload, [xssx for xssx in xssy.strip().split(self.xss_payload) if xssx])
                colorful_xss = self.color_xss(xssy)
                print(f"{Color.good} {colorful_xss}")
        elif xssi['waf_matches']:
            print(f"{Color.bad} {xssy}")
        #elif xssy == 'Blind':
        #    print(f"{Color.good} Successfully executed")
