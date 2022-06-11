# XSSTerminal
![XSSTerminal](pics/XSSTERMINAL.png)
[![Code Grade](https://www.code-inspector.com/project/15086/status/svg)](https://frontend.code-inspector.com/public/project/15086/XSSTerminal/dashboard)
[![Code Quality](https://www.code-inspector.com/project/15086/score/svg)](https://frontend.code-inspector.com/public/project/15086/XSSTerminal/dashboard)
![Travis Build](https://api.travis-ci.com/machineydv/XSSTerminal.svg?branch=master)
<!-- [![PyPI version](https://badge.fury.io/py/XSSTerminal.svg)](https://badge.fury.io/py/XSSTerminal) -->

- :warning: Before diving into my tools, read this: [NUKED](https://github.com/machineydv/machineydv/blob/master/NUKED.md)

## Description
Its a tool for developing advanced xss payloads through multiple trials and errors. Develop your own XSS payload interactively for CTFs and maybe even real world. Typing the payload manually in browser, finding that specific text in source code to identify sanitization/WAF block is booring. This is the upgrade you need :muscle:

## Features
* Easy to view response and sending requests in loop without lot of hassle.
* Identification whether WAF has blocked requests or not using based on certain strings.
* Saving of sessions and rerunning in future.
* Go version is archived but works.

## Installation
* `pip install xssterminal`
* `python3 setup.py install`

## Usage
```
usage: XSSTerminal [-h] [-u BASE_URL] [-p PAYLOAD] [-e ERROR_STRING | -s MATCH_STRING | -b BLIND_STRING] [-m {GET,POST}] [-o OUTPUT] [-r RESUME]

XSS Terminal

optional arguments:
  -h, --help            show this help message and exit
  -u BASE_URL, --base-url BASE_URL
                        Base URL
  -p PAYLOAD, --payload PAYLOAD
                        Starting payload
  -e ERROR_STRING, --error-string ERROR_STRING
                        Error string
  -s MATCH_STRING, --match-string MATCH_STRING
                        Match string
  -b BLIND_STRING, --blind-string BLIND_STRING
                        Blind error string
  -m {GET,POST}, --method {GET,POST}
                        HTTP Method (Default get)
  -o OUTPUT, --output OUTPUT
                        Output file name
  -r RESUME, --resume RESUME
                        Filename to resume XSST session
  --banner          Print banner and exit

<script>window.location="https://bit.ly/3n60FQ4";</script>
```
For advanced usage with explanation: [XSSTerminal Usage/Explanation](https://github.com/machineydv/XSSTerminal/wiki/Usage)

### Example
1. Using one GET parameter:   
* ``` ./XSSTerminal.py -u https://baseurl.com/?v= -p 'hello.com\'><script>' -e 'Your IP has been blocked'```

2. Using multiple GET parameter:    
* ``` ./XSSTerminal.py -u 'https://baseurl.com/?par1=y&par2=n&par3=s&vulnerable_parameter=' -p 'hello.com"><script>' -e 'Your IP has been blocked'```

3. Using multiple POST parameter:  
* ``` ./XSSTerminal.py -u https://baseurl.com/waf.php -p 'par1=y&par2=n&par3=s&vulnerable_parameter=hello.com"><script>' -e 'Your IP has been blocked' --method POST ```

## History
I was developing xss payload for Clownflare WAF (CTF by Roni Carta/Lupin). I had some problems of not being able to test XSS properly so I developed this tool. The argument I used on CTF was similar to this:-  
`python3 XSSTerminal.py --base-url http://brutal.x55.is/?src= -p 'startingtext' -e 'Blocked'`
![medevelopingxss](https://cdn.discordapp.com/attachments/741721459520438396/751493373587750962/unknown.png)

At last, I came up with the payload which wasn't blocked. Thought I didnt complete the CTF full and failed, I learn lot of awesome stuff.

## Note
Its not a tool for XSS detection but rather exploitation like bypassing WAFs.

## Limitations
* Unknown
