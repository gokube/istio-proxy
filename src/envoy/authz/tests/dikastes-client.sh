#!/bin/bash

BIN="/usr/local/bin"
WDIR="/var/lib/dikastes/envoy"
DEBUG="-l debug"

# start the python echo server
python ${BIN}/echo.py 2>&1 &
# start envoy
cd ${WDIR}
${BIN}/envoy -c "envoy.json" "${DEBUG}"
