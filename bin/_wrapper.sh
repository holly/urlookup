#!/usr/bin/env bash

set -e
set -o pipefail
set -C

CMDS=("urlpagediff" "urlookup" "urlh3check")

SCRIPTDIR=$(cd $(dirname $0) && pwd)
URLOOKUPDIR="$HOME/.urlookup"
PREFIX="$URLOOKUPDIR/local"
OPENSSL="$SCRIPTDIR/openssl"
export PYTHONPATH="$PYTHONPATH:$SCRIPTDIR/../lib"
export LD_LIBRARY_PATH="$PREFIX/lib64:$PREFIX/lib"
export URLOOKUPDIR
#export SSL_CERT_DIR="$($OPENSSL version -d | awk '{ print $2 }')/certs"
#export SSL_CERT_FILE=$SSL_CERT_DIR/ca-bundle.crt


for CMD in ${CMDS[@]}; do
	if [[ $CMD = $(basename $0) ]]; then
		for EXT in ".py" ".sh" ".pl"; do
			SCRIPT="$SCRIPTDIR/_${CMD}${EXT}"
			if [[ -f $SCRIPT ]] && [[ -x $SCRIPT ]]; then
				exec $SCRIPT $@
			fi
		done
	fi
done
