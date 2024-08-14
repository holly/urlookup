# urlookup

urlookup is a nice lookup tool that can obtain various information and screenshots about a website by specifying a URL, including whois, DNSBL, geolocation, TLS encryption and connection methods, and more

## Features

retrieving http/dns/thirdparty services information to display json format.

* http
  * response header
  * cert information
  * tls version
  * http/1.1, http/2, http/3 check
  * brotli support check
* dns
  * forward lookup
  * dns reverse lookup
* dnsbl
* whois (require whois command)
* geoip (require [MAXMIND](https://www.maxmind.com/en/home) GEOIP_LICENSE_KEY)
* virustotal (require [VIRUSTOTAL](https://www.virustotal.com/) VT_API_KEY)
* HTML tags(meta, link, script) information
* Save ScreenShot(using chrome, chromedriver and selenium)
  * Normal(1920 x 1080)
  * Vertical FullScreen ScreenShot
* WordPress
  * version
  * theme
  * plugins
* [LightHouse](https://github.com/GoogleChrome/lighthouse) summary (require lighthouse cli)

### Usage

result to json format.

```shell
usage: _urlookup.py [-h] [-v] [--verbose] [-E ENVFILE] [--dnsbl] [-] [-D GEOIP_DATADIR] [--download-geoip-mmdb] [-L]
                    [--lighthouse-strategy {mobile,desktop}] [-N] [-W] [--virustotal] [--wordpress-details] [--screenshot SCREENSHOT]
                    [--fullscreenshot FULLSCREENSHOT]
                    url

A tool that can dig up all sorts of info about URLs, ya see!

positional arguments:
  url                   The URL to process

options:
  -h, --help            show this help message and exit
  -v, --version         show program's version number and exit
  --verbose             verbose output
  -E ENVFILE, --envfile ENVFILE
                        Read urlookup environ variable file
  --dnsbl               Enable dnsbl check
  -G, --geoip           Enable GeoIP information
  -D GEOIP_DATADIR, --geoip-datadir GEOIP_DATADIR
                        GeoIP mmdb data directory. default:/usr/share/GeoIP
  --download-geoip-mmdb
                        Download GeoIP mmdb data to GeoIP mmdb data directory. require `GEOIP_LICENSE_KEY` environment variable
  -L, --lighthouse      Enable lighthouse information. require lighthouse command
  --lighthouse-strategy {mobile,desktop}
                        lighthouse strategy type [mobile or desktop] default:mobile
  -N, --no-redirect     Disable auto redirect
  -W, --whois           Enable whois information
  --virustotal          Enable virustotal information. require `VT_API_KEY` environment variable
  --wordpress-details   Enable wordpress details(version, theme, plugins)
  --screenshot SCREENSHOT
                        Save to the screenshot image
  --fullscreenshot FULLSCREENSHOT
                        Save to the fullscreenshot image
```

### Example

#### normal

```shell
$ bin/urlookup https://example.com/
```

output json sample is [here](https://github.com/holly/urlookup/blob/main/sample/example.com.json).

#### screenshot

```shell
$ bin/urlookup https://example.com/ --screenshot=sample/example.com.png
```
screenshot sample is [here](https://github.com/holly/urlookup/blob/main/sample/example.com.png).

#### all options (exclude --wordpress-details)


```shell
# setup .env
$ cat <<EOL >.env
VT_API_KEY=your_virustotal_api_key
GEOIP_LICENSE_KEY=your_maxmind_api_key
EOL

# auto read .env
$ bin/urlookup https://example.com/ --dnsbl --download-geoip=~/.urlookup/local/share/GeoIP --geoip --whois --virustotal --lighthouse --lighthouse-strategy=desktop
```

screenshot sample is [here](https://github.com/holly/urlookup/blob/main/sample/example.com_all.json).

#### wordpress details

```shell
$ bin/urlookup https://your-wordpress-site.com/ --wordpress-details

output json sample is [here](https://github.com/holly/urlookup/blob/main/sample/wordpress_details_site.json).
```

## Dependencies

for ubuntu

### build packages

* libtool
* autoconf
* pkg-config
* automake
* make
* cmake
* curl
* git
* gcc
* build-essential

#### fonts

* fonts-noto-cjk
* fonts-mplus
* fonts-ipafont-gothic
* fonts-ipafont-mincho
* fonts-ipaexfont-gothic
* fonts-ipaexfont-mincho
* fonts-vlgothic

### chronium

* libatk1.0-0
* libatk-bridge2.0-0
* libasound2
* libpango1.0-0
* libcups2
* libxcomposite-dev
* libxdamage1
* libxrandr2
* libxkbcommon-x11-0
* libgbm-dev

### (optional) official google chrome

The latest Selenium automatically installs Chrome and Chromedriver, but if you want to pre-install the official Google Chrome on your system, execute the following command.

#### add gpg key

```shell
sudo wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | sudo gpg --dearmour -o /usr/share/keyrings/google-keyring.gpg
sudo sh -c 'echo "deb [arch=amd64 signed-by=/usr/share/keyrings/google-keyring.gpg] http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google-chrome.list'
```

#### install google-chrome

```shell
sudo apt -y update && sudo apt -y upgrade && sudo apt install -y google-chrome-stable
```

### (optional) build python using pyenv

* zlib1g-dev
* libbz2-dev
* libsqlite3-dev

## install

```shell
git clone https://github.com/holly/urlookup.git
cd urlookup
./build.sh
```

### about build.sh

We will install an HTTP/3-compatible version of `curl` and build it so that we can perform HTTP/3 communication using the `pycurl` module in Python."

These will be installed in `${HOME}/.urlookup/local`.

#### install middleware list

* [openssl](https://github.com/openssl/openssl)
* [nghttp2](https://github.com/nghttp2/nghttp2)
* [nghttp3](https://github.com/ngtcp2/nghttp3)
* [brotli](https://github.com/google/brotli)
* [curl](https://curl.se/)
* [pycurl](http://pycurl.io/docs/latest/index.html)
* python modules (from [requirements.txt](https://github.com/holly/urlookup/blob/main/requirements.txt))

#### make openssl directory

Generate an `SSL_CERT_DIR` that the OpenSSL built in `${HOME}/.urlookup/local/ssl/certs` can recognize.
This is executed by `build.sh` through [mkcertdir.pl](https://github.com/holly/urlookup/blob/main/mkcertdir.pl).

## License

urlookup is licensed under the MIT License, which means that you are free to get and use it for commercial and non-commercial purposes as long as you fulfill its conditions.

See the LICENSE.txt file for more details.
