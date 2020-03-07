#!/usr/bin/env python

__author__ = "DFIRSec (@pulsecode)"
__version__ = "1.8"
__description__ = "Extract Indicators of Compromise (IOCs) from PDF documents."

import argparse
import io
import re
import sys
from ipaddress import IPv4Address

import pdfplumber
from colorama import Fore, Style, init

from regxref import regex

# Initizlize colorama
init()


class Termcolor:
    # Unicode Symbols and colors
    BOLD = Fore.LIGHTWHITE_EX
    CYAN = Fore.CYAN
    GRAY = Fore.LIGHTBLACK_EX
    GREEN = Fore.LIGHTGREEN_EX
    RED = Fore.RED
    YELLOW = Fore.LIGHTYELLOW_EX
    RESET = Style.RESET_ALL
    SEP = f"{GRAY}--------------{RESET}"
    DOTSEP = f"{GRAY}{'.' * 20}{RESET}"
    FOUND = CYAN + "\u2BA9 " + RESET


# Initialize termcolors
tc = Termcolor()


def processor(regex, text):
    return [x.group() for x in re.finditer(regex, text)]


def extractor(file):
    with pdfplumber.open(file) as pdf:
        for pages in pdf.pages:
            yield pages.extract_text()


def main(pdf_doc):
    try:
        count = 0
        print(f"{tc.DOTSEP}\n{tc.GREEN} [ Gathering IOCs ]{tc.RESET}")
        pages = [page for page in extractor(file=pdf_doc)]
        text = ''.join(pages)

        patterns = {
            'ARABIC': processor(regex(_type='arabic'), text),
            'ARCHIVE': processor(regex(_type='archive'), text),
            'BINARIES': processor(regex(_type='binary'), text),
            'BTC': processor(regex(_type='btc'), text),
            'CHINESE': processor(regex(_type='chinese'), text),
            'CYRILLIC': processor(regex(_type='cyrillic'), text),
            'DOMAINS': processor(regex(_type='domain'), text),
            'EMAILS': processor(regex(_type='email'), text),
            'IMAGES': processor(regex(_type='image'), text),
            'IPV4': processor(regex(_type='ipv4'), text),
            'MD5': processor(regex(_type='md5'), text),
            'OFFICE/PDF': processor(regex(_type='office'), text),
            'SCRIPT': processor(regex(_type='script'), text),
            'SHA1': processor(regex(_type='sha1'), text),
            'SHA256': processor(regex(_type='sha256'), text),
            'URL': processor(regex(_type='url'), text),
            'WEB FILES': processor(regex(_type='webfile'), text),
            'WIN DIRS': processor(regex(_type='windir'), text)
        }

        # Attempt to detect arabic characters
        if patterns.get('ARABIC'):
            count += 1
            arabic = ''.join(patterns.get('ARABIC'))
            print(f"\n{tc.FOUND}{tc.BOLD}ARABIC{tc.RESET}\n{tc.SEP}\n{arabic}")  # nopep8
            patterns.pop('ARABIC')  # remove from dict to not repeat pattern

        # Attempt to detect cyrillic characters
        if patterns.get('CYRILLIC'):
            count += 1
            cyrillic = ''.join(patterns.get('CYRILLIC'))
            print(f"\n{tc.FOUND}{tc.BOLD}CYRILLIC{tc.RESET}\n{tc.SEP}\n{cyrillic}")  # nopep8
            patterns.pop('CYRILLIC')  # remove from dict to not repeat pattern

        # Attempt to detect chinese characters
        if patterns.get('CHINESE'):
            count += 1
            chinese = ''.join(patterns.get('CHINESE'))
            print(f"\n{tc.FOUND}{tc.BOLD}CHINESE{tc.RESET}\n{tc.SEP}\n{chinese}")  # nopep8
            patterns.pop('CHINESE')  # remove from dict to not repeat pattern

        for key, pattern in patterns.items():
            if pattern:
                count += 1
                sorted_set = sorted(set(pattern))
                pattern = '\n'.join(sorted_set)
                print(f"\n{tc.FOUND}{tc.BOLD}{key}{tc.RESET}\n{tc.SEP}\n{pattern}")  # nopep8

        if count == 0:
            print(f"{tc.YELLOW}= No IOCs found ={tc.RESET}")

    except FileNotFoundError:
        sys.exit(f"{tc.RED}[ERROR]{tc.RESET} No such file: {pdf_doc}")  # nopep8
    except Exception as err:
        print(f"{tc.RED}[ERROR]{tc.RESET} {err}") 
    except KeyboardInterrupt:
        sys.exit()


if __name__ == "__main__":
    banner = fr"""
        ____     ____   ______
       / __ \   /  _/  / ____/
      / /_/ /   / /   / __/
     / ____/  _/ /   / /___
    /_/      /___/  /_____/

    PDF IOC Extractor v{__version__}
    """

    print(f"{tc.CYAN}{banner}{tc.RESET}")

    parser = argparse.ArgumentParser(description="PDF IOC Extractor")
    parser.add_argument(dest='pdf_doc', help="Path to single PDF document")  # nopep8
    args = parser.parse_args()

    if len(sys.argv[1:]) == 0:
        parser.print_help()
        parser.exit()

    main(pdf_doc=args.pdf_doc)
