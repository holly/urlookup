#!/usr/bin/env python

import certifi
import concurrent.futures
import ctypes
import dns.resolver
import dns.reversename
import glob
import hashlib
import importlib
import inspect
import json
import logging
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tarfile
import time
import tldextract
import traceback
import urllib
import warnings
from bs4 import BeautifulSoup
from datetime import datetime, timezone
from dotenv import load_dotenv
from io import BytesIO

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager

from .wordpress_plugin_patterns import WORDPRESS_PLUGIN_PATTERNS

CAFILE           = certifi.where()
DNSBL_BY_IPS     = [ "bl.spamcop.net", "b.barracudacentral.org", "zen.spamhaus.org", "bl.nordspam.com", "multi.uribl.com" ]
DNSBL_BY_DOMAINS = [ "dbl.spamhaus.org", "dbl.nordspam.com", "multi.uribl.com", "uribl.spameatingmonkey.net", "uribl.rspamd.com" ]
ERROR_STATUS          = 599
GEOIP_DATADIR         = "/usr/share/GeoIP"
GEOIP_EDITION_IDS     = [ "GeoLite2-ASN", "GeoLite2-City" ]
GEOIP_DOWNLOAD_URL    = "https://download.maxmind.com/app/geoip_download?edition_id={geoip_edition_id}&license_key={geoip_license_key}&suffix=tar.gz"
GOOGLEMAP_URL         = "https://www.google.com/maps/search/?api=1&query={latitude},{longitude}"
LIGHTHOUSE_CMD        = shutil.which("lighthouse")
LIGHTHOUSE_REPORT_URL = "https://googlechrome.github.io/lighthouse/viewer/?psiurl={psiurl}&strategy={strategy}&category=performance&category=accessibility&category=best-practices&category=seo&locale=ja"
MAX_WORKERS           = os.cpu_count() * 2
RESOLVER_TIMEOUT      = 30.0
RESOLVER_NAMESERVERS  = [ "8.8.8.8", "8.8.4.4" ]
SELENIUM_CACHEDIR     = os.path.join(os.environ["HOME"], ".cache/selenium")
USER_AGENT            = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
WHOIS_CMD             = shutil.which("whois")
X_URL                 = "https://x.com/{user}"
VERSION               = 0.92

CURL_HTTP1_1 = False
CURL_HTTP2   = False
CURL_HTTP3   = False

def _header_function(header_line):

    global CURL_HTTP3
    global CURL_HTTP2
    global CURL_HTTP1_1
    header_line = header_line.decode("iso-8859-1").strip()
    if re.match(r'^HTTP/3 .*', header_line):
        CURL_HTTP3  = True
    if re.match(r'^HTTP/2 .*', header_line):
        CURL_HTTP2  = True
    if re.match(r'^HTTP/1\.1 .*', header_line):
        CURL_HTTP1_1  = True


class URLookUp:

    def __init__(self, vt_api_key=None, geoip_license_key=None, geoip_datadir=GEOIP_DATADIR, verbose=False):

        if "GEOIP_LICENSE_KEY" in os.environ:
            self.geoip_license_key = os.environ["GEOIP_LICENSE_KEY"]
        if "VT_API_KEY" in os.environ:
            self.vt_api_key = os.environ["VT_API_KEY"]

        if vt_api_key:
            self.vt_api_key = vt_api_key
        if geoip_license_key:
            self.geoip_license_key = geoip_license_key
        self.geoip_datadir = geoip_datadir

        logger = logging.getLogger(__name__)
        st_handler = logging.StreamHandler()
        st_handler.setFormatter(logging.Formatter("%(levelname)-9s  %(asctime)s  %(message)s"))
        logger.addHandler(st_handler)

        self.logger = logger
        self.verbose = verbose

    @property
    def geoip_datadir(self):
        return self._geoip_datadir

    @property
    def geoip_license_key(self):
        return self._geoip_license_key

    @property
    def vt_api_key(self):
        return self._vt_api_key

    @property
    def logger(self):
        return self._logger

    @property
    def verbose(self):
        return self._verbose

    @geoip_datadir.setter
    def geoip_datadir(self, geoip_datadir):
        if not os.path.exists(geoip_datadir):
            os.makedirs(geoip_datadir, exist_ok=True)
        if not os.path.isdir(geoip_datadir):
            raise RuntimeError("args is not directory")

        self._geoip_datadir = geoip_datadir


    @geoip_license_key.setter
    def geoip_license_key(self, geoip_license_key):
        self._geoip_license_key = geoip_license_key


    @vt_api_key.setter
    def vt_api_key(self, vt_api_key):
        self._vt_api_key = vt_api_key

    @verbose.setter
    def verbose(self, verbose):
        if verbose:
            self.logger.setLevel(logging.DEBUG)
        else:
            self.logger.setLevel(logging.INFO)
        self._verbose = True

    @logger.setter
    def logger(self, logger):
        if not isinstance(logger, logging.Logger):
            raise TypeError("logger is not logging.Logger instance")
        self._logger = logger


    def domain2apexdomain(self, domain):
        extract = tldextract.extract(domain)
        return "{}.{}".format(extract.domain, extract.suffix)

    def download_geoip_mmdb(self):

        start_time = time.time()

        if not self.geoip_license_key:
            raise RuntimeError("geoip_license_key property is not set")

        for geo_edition_id in GEOIP_EDITION_IDS:
            url = GEOIP_DOWNLOAD_URL.format(geoip_edition_id=geo_edition_id, geoip_license_key=self.geoip_license_key)
            download_file = os.path.join(self.geoip_datadir, (geo_edition_id + ".mmdb"))
            self.logger.debug("download url: {}".format(url))
            res = self.make_response(url)
            tar_gz_file = BytesIO(res.read())

            with tarfile.open(fileobj=tar_gz_file, mode="r:gz") as tar:
                for member in tar.getmembers():
                    p = re.compile(r'.+\/.*\.mmdb$')
                    if not p.match(member.name):
                        continue
                    with tar.extractfile(member) as f:
                        with open(download_file, "wb") as outfile:
                            outfile.write(f.read())

            self.logger.debug("save to {}".format(download_file))

        self.logger.debug("{} end. ({} sec)".format(inspect.currentframe().f_code.co_name, time.time() - start_time))
        return True

    def _dnsbl(self, val):

        resolver = self.make_resolver()
        text = ""
        try:
            answers = resolver.resolve(val, "A")
            for rdata in answers:
                text = rdata.to_text()

        except dns.resolver.NXDOMAIN as e:
            text = "NXDOMAIN"
        return text


    def dnsbl_by_ipv4(self, ipv4):

        start_time = time.time()
 
        data = {}
        tmp = ipv4.split(".")
        tmp.reverse()
        reverse_ipv4 = ".".join(tmp)
        #resolver = self.make_resolver()
        #for dnsbl in DNSBL_BY_IPS:
        #    try:
        #        check_hostname = "{}.{}".format(reverse_ipv4, dnsbl)
        #        answers = resolver.resolve(check_hostname, "A")
        #        for rdata in answers:
        #            data[dnsbl] = rdata.to_text()
        #
        #    except dns.resolver.NXDOMAIN as e:
        #        data[dnsbl] = "NXDOMAIN"
        #domains = [ "{}.{}".format(reverse_ipv4, dnsbl) for dnsbl in DNSBL_BY_IPS ]
        domains = []
        for dnsbl in DNSBL_BY_IPS:
            check_domain = "{}.{}".format(reverse_ipv4, dnsbl)
            domains.append(check_domain)
            self.logger.debug("dnsbl check domain: {}".format(check_domain))

        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            results = executor.map(self._dnsbl, domains)
            for dnsbl, text in zip(DNSBL_BY_IPS, results):
                data[dnsbl] = text

        self.logger.debug("{} end. ({} sec)".format(inspect.currentframe().f_code.co_name, time.time() - start_time))
        return data


    def dnsbl_by_domain(self, domain):

        start_time = time.time()

        data = {}
        #resolver = self.make_resolver()
        #for dnsbl in DNSBL_BY_DOMAINS:
        #    try:
        #        check_domain = "{}.{}".format(domain, dnsbl)
        #        answers = resolver.resolve(check_domain, "A")
        #        for rdata in answers:
        #            data[dnsbl] = rdata.to_text()
        #
        #    except dns.resolver.NXDOMAIN as e:
        #        data[dnsbl] = "NXDOMAIN"
        #domains = [ "{}.{}".format(domain, dnsbl) for dnsbl in DNSBL_BY_DOMAINS ]
        domains = []
        for dnsbl in DNSBL_BY_DOMAINS:
            check_domain = "{}.{}".format(domain, dnsbl)
            domains.append(check_domain)
            self.logger.debug("dnsbl check domain: {}".format(check_domain))

        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            results = executor.map(self._dnsbl, domains)
            for dnsbl, text in zip(DNSBL_BY_DOMAINS, results):
                data[dnsbl] = text

        self.logger.debug("{} end. ({} sec)".format(inspect.currentframe().f_code.co_name, time.time() - start_time))
        return data


    def _execute_cmd(self, cmd, capture_output=True, text=True, env=None):

        res = subprocess.run(cmd, capture_output=capture_output, text=text, env=env)
        data = { "returncode": res.returncode, "stdout": res.stdout, "stderr": res.stderr }
        return data

    def execute_lighthouse(self, url, desktop=False, chrome_binary=None):

        if not os.access(LIGHTHOUSE_CMD, os.X_OK):
            raise RuntimeError("lighthouse command is not executable")

        env = { "PATH": "/usr/bin:/bin" }
        cmd = [LIGHTHOUSE_CMD, url, "--quiet", "--output", "json", "--chrome-flags=\"--headless\"" ]
        if desktop:
            cmd = cmd + ["--preset", "desktop"]
        if chrome_binary:
            env["CHROME_PATH"] = chrome_binary
        data = self._execute_cmd(cmd, capture_output=True, text=True, env=env)
        return data


    def execute_whois(self, val):

        if not os.access(WHOIS_CMD, os.X_OK):
            raise RuntimeError("whois command is not executable")

        return self._execute_cmd([WHOIS_CMD, val])


    def geoip_by_ipv4(self, ipv4):

        start_time = time.time()

        db = importlib.import_module("geoip2.database")
        data = {}
        for mmdb in [ "GeoLite2-ASN.mmdb", "GeoLite2-City.mmdb" ]:

            self.logger.debug("read {}".format(os.path.join(self.geoip_datadir, mmdb)))

            with db.Reader(os.path.join(self.geoip_datadir, mmdb)) as reader:
                if mmdb == "GeoLite2-ASN.mmdb":
                    data["asn"] = {}
                    res = reader.asn(ipv4)
                    data["asn"]["autonomous_system_number"] = res.autonomous_system_number
                    data["asn"]["autonomous_system_organization"] = res.autonomous_system_organization

                if mmdb == "GeoLite2-City.mmdb":
                    data["city"] = { "continent": {}, "country": {}, "location": {} }
                    res = reader.city(ipv4)
                    data["city"]["continent"]["code"] = res.continent.code
                    data["city"]["continent"]["name"] = res.continent.names["en"]
                    data["city"]["country"]["geoname_id"]  = res.country.geoname_id
                    data["city"]["country"]["iso_code"]  = res.country.iso_code
                    data["city"]["country"]["name"]  = res.country.names["en"]
                    data["city"]["location"]["accuracy_radius"]  = res.location.accuracy_radius
                    data["city"]["location"]["latitude"]  = res.location.latitude
                    data["city"]["location"]["longitude"]  = res.location.longitude
                    data["city"]["location"]["time_zone"]  = res.location.time_zone


        data["googlemap_url"] = GOOGLEMAP_URL.format(latitude=data["city"]["location"]["latitude"], longitude=data["city"]["location"]["longitude"])

        self.logger.debug("{} end. ({} sec)".format(inspect.currentframe().f_code.co_name, time.time() - start_time))
        return data



    def head_information_by_html(self, html):

        start_time = time.time()

        data = {}
        bs = BeautifulSoup(html, "lxml")
        data["title"] = bs.find("title").string
        data["meta"] = {}
        data["link"] = {}
        data["script"] = []

        # meta 
        for name in [ "keywords", "description", "google-site-verification", "twitter:image", "twitter:title", "twitter:card", "twitter:site", "twitter:creator", "zenn:image", "zenn:description" ]:
            elem = bs.find("meta", attrs={"name": name})
            if elem:
                data["meta"][name] = elem.get("content")


        elems = bs.find_all("meta", attrs={"name": "generator"})
        if elems:
            for elem in elems:
                if not "generator" in data["meta"]:
                    data["meta"]["generator"] = []
                data["meta"]["generator"].append(elem.get("content"))

        for prop in [ "fb:app_id", "og:locale", "og:title", "og:type", "og:description", "og:url", "og:site_name", "og:image" ]:
            elem = bs.find("meta", attrs={"property": prop})
            if elem:
                data["meta"][prop] = elem.get("content")

        # for meta wix
        for prop in [ "X-Wix-Meta-Site-Id", "X-Wix-Application-Instance-Id", "X-Wix-Published-Version" ]:
            elem = bs.find("meta", attrs={"http-equiv": prop})
            if elem:
                data["meta"][prop] = elem.get("content")

        # for link wordpress and other
        for prop in [ "https://api.w.org/", "EditURI", "wlwmanifest", "canonical", "shortcut icon", "icon", "apple-touch-icon" ]:
            elem = bs.find("link", attrs={"rel": prop})
            if elem:
                data["link"][prop] = elem.get("href")

        # for link
        for prop in [ "preload", "stylesheet", "dns-prefetch", "preconnect", "author", "alternate" ]:
            elems = bs.find_all("link", attrs={"rel": prop})
            if elems:
                for elem in elems:
                    if not prop in data["link"]:
                        data["link"][prop] = []
                    data["link"][prop].append(elem.get("href"))

        # for script
        elems = bs.find_all("script")
        if elems:
            for elem in elems:
                src = elem.get("src")
                if src:
                    data["script"].append(src)

        self.logger.debug("{} end. ({} sec)".format(inspect.currentframe().f_code.co_name, time.time() - start_time))
        return data



    def http_versions_by_url(self, url):

        start_time = time.time()

        #ctypes.CDLL(os.path.join(PREFIXDIR, "lib64/libcrypto.so"))
        #ctypes.CDLL(os.path.join(PREFIXDIR, "lib64/libssl.so"))
        #ctypes.CDLL(os.path.join(PREFIXDIR, "lib/libcurl.so"))
        pycurl = importlib.import_module("pycurl")
        data = { }

        for http_version in [ pycurl.CURL_HTTP_VERSION_1_1, pycurl.CURL_HTTP_VERSION_2, pycurl.CURL_HTTP_VERSION_3 ]:

            buffer = BytesIO()
            curl = pycurl.Curl()
            curl.setopt(curl.URL, url)
            curl.setopt(curl.CUSTOMREQUEST, "HEAD")
            curl.setopt(curl.NOBODY, True)
            curl.setopt(curl.CAINFO, CAFILE)
            curl.setopt(curl.HEADERFUNCTION, _header_function)
            curl.setopt(pycurl.HTTP_VERSION, http_version)
            curl.setopt(curl.WRITEDATA, buffer)
            curl.perform()
            #status_code = curl.getinfo(pycurl.RESPONSE_CODE)
            #response = buffer.getvalue().decode('utf-8')
            curl.close()


            if http_version == pycurl.CURL_HTTP_VERSION_1_1 and CURL_HTTP1_1:
                data["h1_1"] = True
            elif http_version == pycurl.CURL_HTTP_VERSION_2 and CURL_HTTP2:
                data["h2"] = True
            elif http_version == pycurl.CURL_HTTP_VERSION_3 and CURL_HTTP3:
                data["h3"] = True

        self.logger.debug("{} end. ({} sec)".format(inspect.currentframe().f_code.co_name, time.time() - start_time))
        return data


    def is_valid_url(self, url):

        parsed = urllib.parse.urlparse(url)
        return all([parsed.scheme, parsed.netloc])

    def is_wordpress_site(self, html):
        patterns = [
            "_wpemojiSettings",
            "/xmlrpc.php?rsd",
            "name=\"generator\" content=\"WordPress",
            "https://api.w.org/",
            "/wp-json",
            "/wp-content",
            "/wp-includes",
            "class=\"wp-image-",
            "class=\"wp-caption",
            "class=\"wp-block",
            "wp-block-library-css"
        ]
        for pattern in patterns:
            if pattern in html:
                return True

        return False

    def lighthouse_by_url(self, url, strategy="mobile", chrome_binary=None, raw_lighthouse=False):

        start_time = time.time()

        desktop = False
        if strategy == "desktop":
            desktop = True
        res  = self.execute_lighthouse(url, desktop=desktop, chrome_binary=chrome_binary)
        if res["returncode"] != 0:
            raise RuntimeError(res["stderr"])

        report = json.loads(res["stdout"])
        if raw_lighthouse:
            return report

        data = { "categories": {}, "audits": {} }
        for category in [ "performance", "seo", "accessibility", "best-practices" ]:
            data["categories"][category] = report["categories"][category]["score"] * 100

        for audit in [ "first-contentful-paint", "largest-contentful-paint", "total-blocking-time", "interactive", "cumulative-layout-shift", "speed-index" ]:
            unit = report["audits"][audit]["numericUnit"]
            if unit == "unitless":
                unit = "millisecond"
            data["audits"][audit] = "{:.3f} {}".format(report["audits"][audit]["numericValue"], unit)

        data["report_url"] = LIGHTHOUSE_REPORT_URL.format(psiurl=urllib.parse.quote(url, safe=""), strategy=strategy)

        self.logger.debug("{} end. ({} sec)".format(inspect.currentframe().f_code.co_name, time.time() - start_time))
        return data

    def make_response(self, url, method="GET", br=False, redirect=True):

        try:
            context = ssl.create_default_context()
            context.load_verify_locations(cafile=CAFILE)
            headers = { "User-Agent": USER_AGENT }
            if br:
                headers["Accept-Encoding"] = "br"

            handlers = [ urllib.request.HTTPSHandler(context=context) ]
            if not redirect:
                handlers.append(NoRedirect())
            opener   = urllib.request.build_opener(*handlers)
            urllib.request.install_opener(opener)
            req = urllib.request.Request(url, method=method, headers=headers)
            #res = urllib.request.urlopen(req, context=context)

            res = opener.open(req)

        except urllib.error.HTTPError as e:
            res = e
        except urllib.error.URLError as e:
            res = DummyResponse(url, title=str(e))
        except ValueError as e:
            res = DummyResponse(url, title=str(e))

        return res


    def make_resolver(self):

        resolver = dns.resolver.Resolver()
        resolver.nameservers = RESOLVER_NAMESERVERS
        resolver.timeout     = RESOLVER_TIMEOUT
        resolver.lifeout     = RESOLVER_TIMEOUT
        return resolver


    def make_selenium(self, w=1920, h=1080):

        options = webdriver.ChromeOptions()
        options.add_argument("--headless")
        options.add_argument("--disable-gpu")
        options.add_argument("--hide-scrollbars")
        options.add_argument("--single-process")
        options.add_argument("--window-size={}x{}".format(w, h))
        options.add_argument("--no-sandbox")
        options.set_capability("browserVersion", "stable") 

        # see https://gammasoft.jp/support/selenium-with-batteries-included/#browser
        #installed_driver = ChromeDriverManager().install()
        #service = Service(installed_driver)
        #driver = webdriver.Chrome(service=service, options=options)
        driver = webdriver.Chrome(options=options)

        return driver


    def _rdata(self, domain, t):

        data = []
        resolver = self.make_resolver()
        try:
            answers = resolver.resolve(domain, t)
            for rdata in answers:
                if t == "A" or t == "AAAA" or t == "CAA" or t == "NS" or t == "SOA":
                    data.append(rdata.to_text())
                if t == "CNAME":
                    data.append(rdata.target.to_text())
                if t == "MX":
                    data.append("{} {}".format(rdata.preference, rdata.exchange))
                if t == "TXT":
                    for string in rdata.strings:
                        data.append(string.decode())

        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN) as e:
            pass

        return data


    def rdata_by_domain(self, domain):

        start_time = time.time()

        data = { }
        #resolver = self.make_resolver()
        #for t in [ "A", "AAAA", "CNAME", "TXT", "CAA", "MX", "NS", "SOA" ]:
        #    try:
        #        answers = resolver.resolve(domain, t)
        #        data[t] = []
        #        for rdata in answers:
        #            if t == "A" or t == "AAAA" or t == "CAA" or t == "NS" or t == "SOA":
        #                data[t].append(rdata.to_text())
        #            if t == "CNAME":
        #                data[t].append(rdata.target.to_text())
        #            if t == "MX":
        #                data[t].append("{} {}".format(rdata.preference, rdata.exchange))
        #            if t == "TXT":
        #                for string in rdata.strings:
        #                    data[t].append(string.decode())
        #
        #    except dns.resolver.NoAnswer as e:
        #        pass
 
        types = []
        for t in [ "A", "AAAA", "CNAME", "TXT", "CAA", "MX", "NS", "SOA" ]:
            types.append(t)
            self.logger.debug("{} IN {}".format(domain, t))

        domains = [ domain for _ in range(len(types)) ]
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            results = executor.map(self._rdata, domains, types)
            for t, result in zip(types, results):
                if len(result) > 0:
                    data[t] = result

        self.logger.debug("{} end. ({} sec)".format(inspect.currentframe().f_code.co_name, time.time() - start_time))
        return data

    def rdata_by_extended_domain(self, domain):

        start_time = time.time()

        data = None
        resolver = self.make_resolver()
        base      = [ "_dmarc", "_adsp._domainkey" ]
        selectors = [ "default", "dkim", "s", "selector", "mail", "s1", "s2" ]
        extends   = base + [ "{}._domainkey".format(s) for s in selectors ] + [ "{}._bimi".format(s) for s in selectors ] 
        #for ext in extends:
        #    try:
        #        answers = resolver.resolve("{}.{}".format(ext, domain), "TXT")
        #        data[ext] = []
        #        for rdata in answers:
        #            for string in rdata.strings:
        #                data[ext].append(string.decode())
        #
        #    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN) as e:
        #        pass

        #domains = [ "{}.{}".format(ext, domain) for ext in extends ]
        domains = []
        for ext in extends:
            check_domain = "{}.{}".format(ext, domain)
            domains.append(check_domain)
            self.logger.debug("{} IN TXT".format(check_domain))

        types = [ "TXT" for _ in range(len(extends)) ]
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            results = executor.map(self._rdata, domains, types)
            for ext, result in zip(extends, results):
                if len(result) > 0:
                    if  not data:
                        data = {}
                    data[ext] = result

        self.logger.debug("{} end. ({} sec)".format(inspect.currentframe().f_code.co_name, time.time() - start_time))
        return data

    def rdata_by_ipv4(self, ipv4):

        start_time = time.time()

        data = { "ipv4": ipv4, "reversename": None  }
        resolver = self.make_resolver()
        try:
            check_domain = dns.reversename.from_address(ipv4)
            self.logger.debug("{} IN PTR".format(check_domain))

            answers = resolver.resolve(check_domain, "PTR")
            for rdata in answers:
                data["reversename"] = rdata.to_text()
        except dns.resolver.NoAnswer as e:
            pass
        except dns.resolver.NXDOMAIN as e:
            pass

        self.logger.debug("{} end. ({} sec)".format(inspect.currentframe().f_code.co_name, time.time() - start_time))
        return data

    def search_chrome_path(self):

        chrome_binaries = list(filter(lambda f: os.path.isfile(f) and os.access(f, os.X_OK), glob.glob(os.path.join(SELENIUM_CACHEDIR, "chrome/**/chrome"), recursive=True)))
        chromedrivers   = list(filter(lambda f: os.path.isfile(f) and os.access(f, os.X_OK), glob.glob(os.path.join(SELENIUM_CACHEDIR, "chromedriver/**/chromedriver"), recursive=True)))
        chrome_binaries_sorted = sorted(chrome_binaries, key=os.path.getmtime, reverse=True)
        chromedrivers_sorted = sorted(chromedrivers, key=os.path.getmtime, reverse=True)
        return { "chrome_binaries": chrome_binaries_sorted,  "chromedrivers": chromedrivers_sorted }

    def ssl_information_by_domain(self, domain, port=443):

        start_time = time.time()

        data = {}
        context = ssl.create_default_context()
        context.load_verify_locations(cafile=CAFILE)
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)
        conn.connect((domain, port))
        cert = conn.getpeercert()

        now = datetime.now(timezone.utc)
        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days_remaining = (not_after - now).days
        data = {}
        data["days_remaining"]  = days_remaining
        data["not_before"]      = cert["notBefore"]
        data["not_after"]       = cert["notAfter"]
        data["serial_number"]   = cert["serialNumber"]
        data["subject_altname"] = []
        for e in cert["subjectAltName"]:
            data["subject_altname"].append(e[1])

        data["subject"] = {}
        for e in cert["subject"]:
            if e[0][0] == "organizationName" :
                data["subject"]["organization_name"] = e[0][1]
            if e[0][0] == "commonName" :
                data["subject"]["common_name"] = e[0][1]

        data["issuer"] = {}
        for e in cert["issuer"]:
            if e[0][0] == "organizationName" :
                data["issuer"]["organization_name"] = e[0][1]
            if e[0][0] == "commonName" :
                data["issuer"]["common_name"] = e[0][1]

        data["pem"] = ssl.DER_cert_to_PEM_cert(conn.getpeercert(binary_form=True))
        conn.close()

        self.logger.debug("{} end. ({} sec)".format(inspect.currentframe().f_code.co_name, time.time() - start_time))
        return data


    def tls_version_by_domain(self, domain, port=443):

        start_time = time.time()

        data = {}

        sock = socket.create_connection((domain, port))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cafile=CAFILE)
        conn = context.wrap_socket(sock, server_hostname=domain)
        data["tls_version"] = conn.version()
        data["cipher"] = conn.cipher()[0]
        conn.close()

        self.logger.debug("{} end. ({} sec)".format(inspect.currentframe().f_code.co_name, time.time() - start_time))
        return data


    def urlparse(self, url):

        parsed = urllib.parse.urlparse(url)
        ret = all([parsed.scheme, parsed.netloc])
        if not ret:
            raise InvalidURLError("{} is invalid url".format(url))

        return parsed


    def vt_by_url(self, url):

        start_time = time.time()

        vt     = importlib.import_module("vt")
        client = vt.Client(self.vt_api_key)
        url_id = vt.url_id(url)
        obj    = client.get_object("/urls/{}", url_id)
        categories = obj.categories
        last_analysis_stats = obj.last_analysis_stats
        last_analysis_date = obj.last_analysis_date

        analysis = client.scan_url(url)
        while True:
            analysis = client.get_object("/analyses/{}", analysis.id)
            if analysis.status == "completed":
                break
            time.sleep(5)

        client.close()
        data = {
            "categories": dict(categories),
            "last_analysis_stats": dict(last_analysis_stats),
            "last_analysis_date": last_analysis_date.strftime("%Y/%m/%d %H:%M:%S"),
            "analysis": { "_id": analysis.get("_id"), "date": analysis.get("date"), "stats": dict(analysis.get("stats")) }
        }

        self.logger.debug("{} end. ({} sec)".format(inspect.currentframe().f_code.co_name, time.time() - start_time))
        return data


    def wordpress_theme_by_url(self, url):

        start_time = time.time()
        self.logger.debug("wordpress theme url: {}".format(url))
        res = self.make_response(url)
        if res.status != 200:
            return None

        data = {}
        start = None
        for line in res.read().decode("utf-8").split("\n"):
            line = line.strip()
            if re.match(r'^/\*', line):
                start = True
            if re.match(r'^\*/', line):
                start = False
            m = re.match(r'^([a-zA-Z0-9 ]+):\s+(.*)$', line)
            if start and m:
                k = m.group(1).replace(" ", "_")
                v = m.group(2)
                data[k] = v
            if not start:
                break

        self.logger.debug("{} end. ({} sec)".format(inspect.currentframe().f_code.co_name, time.time() - start_time))
        return data


    def _wordpress_plugin_by_html_or_url(self, plugin, patterns, html, wp_top_url):

        data = None
        for pattern in patterns["html_patterns"]:
            if pattern not in html: 
                continue
            if not data:
                data = { "from_html": [] }
            data["from_html"].append(pattern)

        if not wp_top_url:
            return plugin, data

        if data:
            # 余計なリクエストを発生させないため、HTMLの中で指定文字列が見つかった場合はreturnする
            return plugin, data

        for pattern in patterns["url_patterns"]:
            time.sleep(0.1)
            plugin_url = wp_top_url + pattern + "readme.txt"
            res = self.make_response(plugin_url)
            if res.status != 200:
                continue
            for line in res.read().decode("utf-8").split("\n"):
                line = line.strip()
                m = re.match(r'^([a-zA-Z0-9 ]+):\s+(.*)$', line)
                if not m:
                    continue
                if not data:
                    data = {}
                k = m.group(1).replace(" ", "_")
                v = m.group(2)
                data[k] = v

        return plugin, data


    def wordpress_plugins_by_html_or_url(self, html, wp_top_url=None):

        start_time = time.time()
        data = {}

        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            #futures = [ executor.submit(self._wordpress_plugin_by_html_or_url, plugin, patterns, html, wp_top_url) for plugin, patterns in WORDPRESS_PLUGIN_PATTERNS.items() ]
            futures = []
            for plugin, patterns in WORDPRESS_PLUGIN_PATTERNS.items():
                self.logger.debug("wordpress plugin url: {}".format(wp_top_url + patterns["url_patterns"][0]))
                futures.append(executor.submit(self._wordpress_plugin_by_html_or_url, plugin, patterns, html, wp_top_url))

            for future in concurrent.futures.as_completed(futures):
                plugin, result = future.result()
                if result:
                    data[plugin] = result

        # for plugin, patterns in WORDPRESS_PLUGIN_PATTERNS.items():

        #     for pattern in patterns["html_patterns"]:
        #         if pattern in html: 
        #             data[plugin] = { "from_html": pattern }
        #             break

        #     if not wp_top_url:
        #         continue

        #     for pattern in patterns["url_patterns"]:
        #         time.sleep(0.1)
        #         plugin_url = wp_top_url + pattern + "readme.txt"
        #         res = self.make_response(plugin_url)
        #         if res.status != 200:
        #             continue
        #         if plugin not in data:
        #             data[plugin] = {}
        #         for line in res.read().decode("utf-8").split("\n"):
        #             line = line.strip()
        #             m = re.match(r'^([a-zA-Z0-9 ]+):\s+(.*)$', line)
        #             if m:
        #                 k = m.group(1).replace(" ", "_")
        #                 v = m.group(2)
        #                 data[plugin][k] = v

        self.logger.debug("{} end. ({} sec)".format(inspect.currentframe().f_code.co_name, time.time() - start_time))
        return data



    def whois_by_ipv4(self, ipv4, raw_whois=False):

        start_time = time.time()

        whoisit = importlib.import_module("whoisit")
        whoisit.bootstrap()
        data =  whoisit.ip(ipv4)
        last_changed_date = data["last_changed_date"]
        registration_date = data["registration_date"]
        data["last_changed_date"] = last_changed_date.strftime("%Y/%m/%d %H:%M:%S")
        if registration_date:
            data["registration_date"] = registration_date.strftime("%Y/%m/%d %H:%M:%S")
        network = data["network"]
        data["network"] = str(network)

        if raw_whois:
            data["raw_whois"] = self.execute_whois(ipv4)

        self.logger.debug("{} end. ({} sec)".format(inspect.currentframe().f_code.co_name, time.time() - start_time))
        return data


    def whois_by_domain(self, domain, raw_whois=False):

        start_time = time.time()

        whois = importlib.import_module("whois")
        data =  whois.whois(domain)
        now = datetime.now()
        expiration_date = data["expiration_date"]
        creation_date  = data["creation_date"]
        updated_date  = data["updated_date"]

        if isinstance(creation_date, list):
            days_since_born = (now - creation_date[0]).days
            data["days_since_born"] = days_since_born
            data["creation_date"] = creation_date[0].strftime("%Y/%m/%d %H:%M:%S")
        elif isinstance(creation_date, datetime):
            days_since_born = (now - creation_date).days
            data["days_since_born"] = days_since_born
            data["creation_date"] = creation_date.strftime("%Y/%m/%d %H:%M:%S")
        elif isinstance(creation_date, str):
            data["creation_date"] = creation_date

        if isinstance(updated_date, list):
            data["updated_date"] = updated_date[0].strftime("%Y/%m/%d %H:%M:%S")
        if isinstance(updated_date, datetime):
            data["updated_date"] = updated_date.strftime("%Y/%m/%d %H:%M:%S")

        if isinstance(expiration_date, list):
            days_remaining = (expiration_date[0] - now).days
            data["days_remaining"] = days_remaining
            data["expiration_date"] = expiration_date[0].strftime("%Y/%m/%d %H:%M:%S")
        if isinstance(expiration_date, datetime):
            days_remaining = (expiration_date - now).days
            data["days_remaining"] = days_remaining
            data["expiration_date"] = expiration_date.strftime("%Y/%m/%d %H:%M:%S")

        if raw_whois:
            data["raw_whois"] = data.text

        self.logger.debug("{} end. ({} sec)".format(inspect.currentframe().f_code.co_name, time.time() - start_time))
        return data


 
class DummyResponse:

    def __init__(self, url, status=ERROR_STATUS, title="Error"):
        self._url     = url
        self._status  = status
        self._title   = title
        self._body    = "<html><head><title>Unsupported Error</title></head><body><h1>{}</h1></body></html>".format(title)
        self._headers = { "content-type": "text/html" }

    def read(self):
        return self._body.encode("utf-8")

    @property
    def headers(self):
        return self._headers

    @property
    def title(self):
        return self._title


    @property
    def url(self):
        return self._url

    @property
    def status(self):
        return self._status

    def close(self):
        pass

    def __str__(self):
        return "status:{} reason:{}".format(self.status, self.title)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class InvalidURLError(Exception):
    pass

class DummyResponseError(Exception):
    pass


def lookup_all(url, dnsbl=False, geoip=False, download_geoip_mmdb=False, redirect=True, whois=False, virustotal=False, wordpress_details=False, lighthouse=False, lighthouse_strategy="mobile", vt_api_key=None, geoip_license_key=None, geoip_datadir=GEOIP_DATADIR, screenshot_path=None, fullscreenshot_path=None, verbose=False):

    start_time = time.time()

    data = {}
    kwargs = {
          "geoip_license_key": geoip_license_key,
          "vt_api_key": vt_api_key,
          "geoip_datadir": geoip_datadir,
          "verbose": verbose
        }
    o = URLookUp(**kwargs)

    if not o.is_valid_url(url):
        raise InvalidURLError("url:{} is invalid".format(url))

    res = o.make_response(url, method="HEAD", br=True, redirect=redirect)

    if res.status == ERROR_STATUS:
        raise RuntimeError(str(res))

    if download_geoip_mmdb:
        o.download_geoip_mmdb()

    data["redir"] = { "redirect": False, "orig_url": url }
    if res.url != url:
        data["redir"]["redirect"] = True
        data["redir"]["last_url"] = res.url

    data["http_response"] = { "status": res.status, "headers": { k: res.headers.get(k) for k in res.headers.keys() } }
    if "Content-Encoding" in data["http_response"]["headers"]:
        data["http_response"]["brotli_support"] = True

    parsed = o.urlparse(res.url)

    apexdomain = o.domain2apexdomain(parsed.hostname)
    data["domains"] = { "domain": parsed.hostname, "apexdomain": apexdomain }

    data["rdata"] = { }
    data["rdata"]["forward_lookup"] = o.rdata_by_domain(parsed.hostname)
    extended_forward_lookup = o.rdata_by_extended_domain(parsed.hostname)
    if extended_forward_lookup:
        data["rdata"]["extended_forward_lookup"] = extended_forward_lookup
    ipv4 = data["rdata"]["forward_lookup"]["A"][0] if "A" in data["rdata"]["forward_lookup"] else None
    if ipv4:
        data["rdata"]["reverse_lookup"] = o.rdata_by_ipv4(ipv4)

    if dnsbl:
        data["dnsbl"] = {}
        data["dnsbl"]["domain"] = o.dnsbl_by_domain(parsed.hostname)
        if ipv4:
            data["dnsbl"]["ipv4"] = o.dnsbl_by_ipv4(ipv4)


    if geoip and ipv4:
        data["geoip"] = o.geoip_by_ipv4(ipv4)

    if whois:
        data["whois"] = {}
        data["whois"]["domain"] = o.whois_by_domain(data["domains"]["apexdomain"])
        if ipv4:
            data["whois"]["ipv4"] = o.whois_by_ipv4(ipv4)

    if virustotal:
        data["virustotal"] = o.vt_by_url(res.url)

    if parsed.scheme == "https":
        data["https"] = {}
        data["https"]["cert"]          = o.ssl_information_by_domain(parsed.hostname)
        data["https"]["tls_version"]   = o.tls_version_by_domain(parsed.hostname)
        data["https"]["http_versions"] = o.http_versions_by_url(res.url)


    if re.match(r'^(2|4|5)\d\d$', str(res.status)) and  re.match(r'^text/html.*', res.headers.get("content-type")):

        driver = o.make_selenium()
        driver.get(res.url)
        html = driver.page_source
        chromes = o.search_chrome_path()

        raw_html_byte = o.make_response(res.url).read()
        data["raw_page_source"] = raw_html_byte.decode("utf-8")
        data["raw_page_source_hash"] = hashlib.sha256(raw_html_byte).hexdigest()
        data["page_source_by_selenium"] = html

        data["html_head"] = o.head_information_by_html(html)

        if screenshot_path or fullscreenshot_path:
            if screenshot_path:
                driver.save_screenshot(screenshot_path)
            if fullscreenshot:
                w = driver.execute_script("return document.body.scrollWidth;")
                h = driver.execute_script("return document.body.scrollHeight;")
                driver.set_window_size(w, h)
                driver.save_screenshot(fullscreenshot_path)
        driver.quit()

        for meta_name in filter(lambda meta_name: re.match(r'twitter:(site|creator)', meta_name), data["html_head"]["meta"].keys()):
            m = re.match(r'^(@)([a-zA-Z0-9_]+)', data["html_head"]["meta"][meta_name])
            if m:
                data["x"] = X_URL.format(user=m.group(2))

        for script_url in data["html_head"]["script"]:
            if re.match(r'/_next/static/', script_url):
                data["site"] = { "app": "nextjs" }
            if re.match(r'/_nuxt/static/', script_url):
                data["site"] = { "app": "nuxtjs" }

        if "generator" in data["html_head"]["meta"]:
            for generator in data["html_head"]["meta"]["generator"]:
                m = re.match(r'^(Hugo|Gatsuby|WordPress)\s+(.+)', generator)
                if m:
                    data["site"] = { "app": m.group(1), "version": m.group(2) }


        if (("site" in data and data["site"]["app"] == "WordPress") or o.is_wordpress_site(html)) and wordpress_details:
            wp_json_url = data["html_head"]["link"]["https://api.w.org/"]
            wp_top_url = wp_json_url.replace("wp-json/", "")

            for url in data["html_head"]["link"]["stylesheet"]:
                m = re.match(r'.*/wp-content/themes/(.*)/styles?\.css', url)
                if m:
                    theme = o.wordpress_theme_by_url(url)
                    data["site"]["theme"] = theme  if theme else { "Theme_Name": m.group(1) }

            data["site"]["plugins"] = o.wordpress_plugins_by_html_or_url(html, wp_top_url=wp_top_url)

        if lighthouse:
            data["lighthouse"] = o.lighthouse_by_url(res.url, strategy=lighthouse_strategy, chrome_binary=chromes["chrome_binaries"][0])

    elif re.match(r'^2\d\d$', str(res.status)) and  re.match(r'^text/.*', res.headers.get("content-type")):
        raw_html_byte = o.make_response(res.url).read()
        data["raw_page_source"] = raw_html_byte.decode("utf-8")
        data["raw_page_source_hash"] = hashlib.sha256(raw_html_byte).hexdigest()

    o.logger.debug("{} end. ({} sec)".format(inspect.currentframe().f_code.co_name, time.time() - start_time))
    return data

