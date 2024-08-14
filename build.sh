#!/usr/bin/env bash

set -e
set -u
set -o pipefail
set -C

PROCS=$(grep -c processor /proc/cpuinfo)
URLOOKUPDIR=$PWD
WORKDIR=$PWD/tmp
PREFIX=$HOME/.urlookup/local
MKCERTDIRPL=$PWD/mkcertdir.pl
PIPREQUIREMENTS=$PWD/requirements.txt

mkdir -p $WORKDIR
cd $WORKDIR
if [[ -d openssl ]]; then
    echo "skip openssl build."
else
    git clone --depth 1 https://github.com/openssl/openssl
    cd openssl
    LDFLAGS="-L$PREFIX/lib:$PREFIX/lib64 -Wl,-rpath,$PREFIX/lib:$PREFIX/lib64,--enable-new-dtags"  ./config --prefix=$PREFIX
    make -j$PROCS
    make install_sw install_ssldirs
    cd ..
fi


if [[ -d nghttp2 ]]; then
    echo "skip nghttp2 build."
else
    git clone https://github.com/nghttp2/nghttp2
    cd nghttp2
    autoreconf -fi
    automake
    autoconf
    ./configure --prefix=$PREFIX --enable-lib-only
    make -j$PROCS
    make install
    cd ..
fi


if [[ -d nghttp3 ]]; then
    echo "skip nghttp3 build."
else
    git clone https://github.com/ngtcp2/nghttp3
    cd nghttp3
    git submodule update --init
    autoreconf -fi
    ./configure --prefix=$PREFIX --enable-lib-only
    make -j$PROCS
    make install
    cd ..
fi


if [[ -d brotli ]]; then
    echo "skip brotli build."
else
    git clone https://github.com/google/brotli.git
    cd brotli
    mkdir out
    pushd out
    cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=$PREFIX -DCMAKE_EXE_LINKER_FLAGS="-L$PREFIX/lib:$PREFIX/lib64 -Wl,-rpath,$PREFIX/lib:$PREFIX/lib64,--enable-new-dtags" ..
    cmake --build . --config Release --target install --parallel $PROCS
    popd
    cd ..
fi

if [[ -d curl ]]; then
    rm -frv ./curl
fi
git clone https://github.com/curl/curl
cd curl
autoreconf -fi
PKG_CONFIG_PATH=$PREFIX/lib/pkgconfig \
LDFLAGS="-L$PREFIX/lib:$PREFIX/lib64 -Wl,-rpath,$PREFIX/lib:$PREFIX/lib64,--enable-new-dtags" \
./configure \
--prefix=$PREFIX \
--with-brotli=$PREFIX \
--with-openssl=$PREFIX \
--with-openssl-quic \
--with-nghttp3 \
--with-zlib --enable-hsts --enable-alt-svc --enable-http-auth --enable-unix-sockets --enable-verbose --enable-http --enable-optimize --enable-get-easy-options --disable-ftp --disable-ldap --disable-rtsp --disable-dict --disable-telnet --disable-tftp --disable-pop3 --disable-imap --disable-smb --disable-smtp --disable-mqtt   --disable-gopher
make -j$PROCS
make install
cd ../

if [[ -d pycurl ]]; then
    rm -frv ./pycurl
fi
git clone https://github.com/pycurl/pycurl
cd pycurl
#python setup.py install --curl-config=$PREFIX/bin/curl-config
PYCURL_CURL_CONFIG=$PREFIX/bin/curl-config pip install .
cd ../

pip install -r $PIPREQUIREMENTS
pip freeze | grep -v pycurl | tail -n +3 | xargs pip install --upgrade

SSL_CERT_DIR="$($PREFIX/bin/openssl version -d | awk '{ print $2 }')"/certs
$MKCERTDIRPL $SSL_CERT_DIR
#pushd $SSL_CERT_DIR
#curl -LO https://raw.githubusercontent.com/puppetlabs/puppet-ca-bundle/main/mk-ca-bundle.pl
#chmod +x mk-ca-bundle.pl
#./mk-ca-bundle.pl
#popd

