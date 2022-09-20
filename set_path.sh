#!/bin/sh
set -e

SCRIPT=$(readlink -f "$0")
SCRIPTPATH=$(dirname "$SCRIPT")

export PATH=$SCRIPTPATH/path:$PATH
export AS=$SCRIPTPATH/path/as
exec "$@"
