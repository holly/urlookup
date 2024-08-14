#!/usr/bin/env python

import argparse
import json
import os
import sys
import urlookup
import warnings
import traceback
from dotenv import load_dotenv, find_dotenv

def main():

    load_dotenv()

    parser = argparse.ArgumentParser(prog=os.path.basename(__file__), description="A tool that can dig up all sorts of info about URLs, ya see!")
    parser.add_argument("url", help="The URL to process")
    parser.add_argument("-v", "--version", action="version", version="%(prog)s {}".format(urlookup.VERSION))
    parser.add_argument("--verbose", action="store_true", help="verbose output")
    parser.add_argument("-E", "--envfile", type=str, help="Read urlookup environ variable file")
    parser.add_argument("--dnsbl", action="store_true", help="Enable dnsbl check")
    parser.add_argument("-G", "--geoip", action="store_true", help="Enable GeoIP information")
    parser.add_argument("-D", "--geoip-datadir", type=str, default=urlookup.GEOIP_DATADIR, help="GeoIP mmdb data directory. default:{}".format(urlookup.GEOIP_DATADIR))
    parser.add_argument("--download-geoip-mmdb", action="store_true", help="Download GeoIP mmdb data to GeoIP mmdb data directory. require `GEOIP_LICENSE_KEY` environment variable")
    parser.add_argument("-L", "--lighthouse", action="store_true", help="Enable lighthouse information. require lighthouse command")
    parser.add_argument("--lighthouse-strategy", type=str, default="mobile", choices=["mobile", "desktop"], help="lighthouse strategy type [mobile or desktop] default:mobile")
    parser.add_argument("-N", "--no-redirect", action="store_true", help="Disable auto redirect")
    parser.add_argument("-W", "--whois", action="store_true", help="Enable whois information")
    parser.add_argument("--virustotal", action="store_true", help="Enable virustotal information. require `VT_API_KEY` environment variable")
    parser.add_argument("--wordpress-details", action="store_true", help="Enable wordpress details(version, theme, plugins)")
    parser.add_argument("--screenshot-path",  type=str, help="Save to the screenshot image")
    parser.add_argument("--fullscreenshot-path",  type=str, help="Save to the fullscreenshot image")

    parser.add_argument("-o", "--output-path",  type=argparse.FileType("w"), help="Save to the output json file")
    #group = parser.add_mutually_exclusive_group()
    #group.add_argument("--screenshot",  type=str, help="Save to the screenshot image")
    #group.add_argument("--fullscreenshot",  type=str, help="Save to the fullscreenshot image")
    args   = parser.parse_args()

    if args.envfile and os.path.isfile(args.envfile):
        load_dotenv(args.envfile)

    data = {}

    try:
        kwargs = {
                "geoip": args.geoip,
                "geoip_datadir": args.geoip_datadir,
                "dnsbl": args.dnsbl,
                "download_geoip_mmdb": args.download_geoip_mmdb,
                "redirect": False if args.no_redirect else True,
                "lighthouse": args.lighthouse,
                "lighthouse_strategy": args.lighthouse_strategy,
                "whois": args.whois,
                "virustotal": args.virustotal,
                "wordpress_details": args.wordpress_details,
                "geoip_datadir": args.geoip_datadir,
                "screenshot_path": args.screenshot_path,
                "fullscreenshot_path": args.fullscreenshot_path,
                "verbose": args.verbose
            }
        #if "GEOIP_LICENSE_KEY" in os.environ:
        #    kwargs["geoip_license_key"] = os.environ["GEOIP_LICENSE_KEY"]
        #if "VT_API_KEY" in os.environ:
        #    kwargs["vt_api_key"] = os.environ["VT_API_KEY"]
        res = urlookup.lookup_all(args.url, **kwargs)
        f = args.output_path if args.output_path else sys.stdout
        print(json.dumps(res, ensure_ascii=False, indent=2), file=f)

    except urlookup.InvalidURLError as e:
        parser.error(str(e))

    except Exception as e:
        warnings.warn(traceback.format_exc())
        sys.exit(str(e))

if __name__ == "__main__":
    main()
