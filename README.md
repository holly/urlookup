# urlookup

A tool that can dig up all sorts of info about URLs, ya see!

## dependencies

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

### build python(using pyenv)

* zlib1g-dev
* libbz2-dev
* libsqlite3-dev

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

#### add gpg key

```shell
sudo wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | sudo gpg --dearmour -o /usr/share/keyrings/google-keyring.gpg
sudo sh -c 'echo "deb [arch=amd64 signed-by=/usr/share/keyrings/google-keyring.gpg] http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google-chrome.list'
```

#### install google-chrome

```shell
sudo apt -y update && sudo apt -y upgrade && sudo apt install -y google-chrome-stable
```


