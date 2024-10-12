#!/usr/bin/env bash

set -e
set -u
set -o pipefail
set -C

SCRIPTDIR=$(cd $(dirname $0) && pwd)
RES=$($SCRIPTDIR/urlookup $1 | jq ".https.http_versions.h3")
STATUS=0
if [[ "$RES" != "true" ]]; then
	STATUS=1
fi
exit $STATUS
