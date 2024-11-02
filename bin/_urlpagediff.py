#!/usr/bin/env python

import argparse
import difflib
import json
import os
import sys
import urlookup
import warnings
import re
import traceback
from dotenv import load_dotenv, find_dotenv

def url2fname(url):
    o = urlookup.URLookUp()
    parsed = o.urlparse(url)
    host = parsed.netloc
    path = parsed.path

    fname = host + path

    # 特殊文字をエスケープ
    # ファイル名に使えない文字をリスト化
    forbidden_chars = r'[<>:"/\\|?*\x00]'

    # 許されない文字をアンダースコアに置換
    fname = re.sub(forbidden_chars, '_', fname)

    # 長いファイル名やURLの一意性を保証するため、ハッシュを追加
    url_hash = o.sha256(url.encode())

    # ファイル名にハッシュを加える
    if not fname.endswith('/'):
        fname += '_'
    fname += url_hash[:8]  # 先頭8文字のハッシュを追加

    # ファイル名の末尾にスラッシュが含まれている可能性があるため、削除
    #if fname.endswith('_'):
    #    fname = file_name[:-1]
    return fname


def read_cache(path):

    with open(path, "r") as f:
        cache = json.load(f)
    return cache


def save_cache(path, res):

    with open(path, "w") as f:
        f.write(json.dumps(res, ensure_ascii=False, indent=2))


def main():

    load_dotenv()

    parser = argparse.ArgumentParser(prog=os.path.basename(__file__), description="A tool that can dig up all sorts of info about URLs, ya see!")
    parser.add_argument("url", help="The URL to process")
    parser.add_argument("-v", "--version", action="version", version="%(prog)s {}".format(urlookup.VERSION))
    parser.add_argument("-E", "--envfile", type=str, help="Read urlookup environ variable file")
    parser.add_argument("-U", "--update",  action="store_true", help="update and store new response json to cache_file(savedir: $HOME/.urlookup/cache)")
    args   = parser.parse_args()

    if args.envfile and os.path.isfile(args.envfile):
        load_dotenv(args.envfile)

    data = {}

    try:
        cache_dir  = os.path.join(os.environ["URLOOKUPDIR"], "cache")
        cache_file = os.path.join(cache_dir, url2fname(args.url))
        os.makedirs(cache_dir, exist_ok=True)
        res = urlookup.lookup_all(args.url, page_source=True)

        if not os.path.isfile(cache_file):
            save_cache(cache_file, res)
            warnings.warn("{} cache is not exists. save new cache to {}.".format(args.url, cache_file))
            sys.exit(2)

        cache = read_cache(cache_file)
        if res["page_source"]["raw_hash"] == cache["page_source"]["raw_hash"]:
            return

        diff_lines = difflib.Differ().compare(cache["page_source"]["selenium_content"].splitlines(), res["page_source"]["selenium_content"].splitlines())
        for line in diff_lines:
            if not re.match(r'^(\+|\-)', line):
                continue
            print(line)
        if args.update:
            save_cache(cache_file, res)
        sys.exit(1)
    except urlookup.InvalidURLError as e:
        parser.error(str(e))

    except Exception as e:
        warnings.warn(traceback.format_exc())
        sys.exit(str(e))

if __name__ == "__main__":
    main()
