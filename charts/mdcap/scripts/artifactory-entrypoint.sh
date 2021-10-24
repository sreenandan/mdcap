#!/bin/bash

set -x
MDCAP_DATA_DIR="/data/"
MDCAPBIN_DIR="/data/artifact/api/v1/mdcapbin/"

if [ ! -e key.pem ];then
    cp /.robin/scripts/certs/* .
fi
cp -R /mdcap/readonly_fns/* $MDCAP_DATA_DIR || 
    { echo "Could not copy scripts from /mdcap/readonly_fns to $MDCAP_DATA_DIR"; exit 1; }

while [ 1 ]; do
    test -d /data &&  mkdir -p $MDCAPBIN_DIR && 
        cp /root/mdcapbin/* ${MDCAPBIN_DIR} && break
    echo "Waiting for directory /data"
    sleep 1

done
exec /mdcap/artifactory 
