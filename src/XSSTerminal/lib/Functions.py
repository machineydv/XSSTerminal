import readline
from prompt_toolkit import prompt as input_prompt
from pygments.lexers.html import HtmlLexer
from prompt_toolkit.lexers import PygmentsLexer
from prompt_toolkit import ANSI

from XSSTerminal.lib.Globals import Color

def xss_input_readline(prompt, text):
         def hook():
             readline.insert_text(text)
             readline.redisplay()
         readline.set_pre_input_hook(hook)
         result = input(prompt)
         readline.set_pre_input_hook()
         return result

def xss_input_prompt_toolkit(prompt, text):
    return input_prompt(ANSI(prompt), default=text, lexer=PygmentsLexer(HtmlLexer))

def banner():
    b = '\x1b[1m\x1b[31m   _  ____________    ______                    _             __\n  | |/ / ___/ ___/   /_  __/__  _________ ___  (_)___  ____ _/ /\n  |   /\\__ \\__ \\     / / / _ \\/ ___/ __ `__ \\/ / __ \\/ __ `/ / \n /   |___/ /__/ /    / / /  __/ /  / / / / / / / / / / /_/ / /  \n/_/|_/____/____/    /_/  \\___/_/  /_/ /_/ /_/_/_/ /_/\\__,_/_/   \n                                                                \n\x1b[0m'
    print(b)

def starter(argv):
    if argv.banner:
        banner()
        exit()
    if not argv.url:
        print(f"{Color.bad} Use --help")
        exit()
    if argv.readline:
        xsstinput = xss_input_readline
    else:
        xsstinput = xss_input_prompt_toolkit
    return argv.url, xsstinput

def exit_handler(*args, filename=None):
    pass
