#!/usr/bin/env python

import argparse
import difflib
import json
import os
import sys
import warnings
import re
import traceback
import urlookup
from dotenv import load_dotenv, find_dotenv

def main():

    load_dotenv()

    parser = argparse.ArgumentParser(prog=os.path.basename(__file__), description="A tool that can dig up all sorts of info about URLs, ya see!")
    parser.add_argument("url", help="The URL to process")
    parser.add_argument("-v", "--version", action="version", version="%(prog)s {}".format(urlookup.VERSION))
    parser.add_argument("-E", "--envfile", type=str, help="Read urlookup environ variable file")
    args   = parser.parse_args()

    if args.envfile and os.path.isfile(args.envfile):
        load_dotenv(args.envfile)

    try:

        o = urlookup.URLookUp()
        if not o.is_valid_url(args.url):
            raise urlookup.InvalidURLError("url:{} is invalid".format(args.url))

        data = o.http_versions_by_url(args.url)
        if "h3" not in data:
            sys.exit(1)

    except urlookup.InvalidURLError as e:
        parser.error(str(e))

    except Exception as e:
        warnings.warn(traceback.format_exc())
        sys.exit(str(e))

if __name__ == "__main__":
    main()
