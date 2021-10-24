#!/bin/sh

export HTTPS=true

mkdir -p ${MDCAP_SSL_CERTS_DIR}
cp /.robin/scripts/certs/* ${MDCAP_SSL_CERTS_DIR}

cd /.robin/scripts/
python logstore.py
