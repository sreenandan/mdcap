#!/bin/sh

cp -r /.robin/scripts/app/gui /root/gui
cd /root/gui


#MDCAP_NGINX_HOST=${ROBINHOST}
#MDCAP_PLAYGROUND_HOST=${MDCAP_NGINX_HOST}
MDCAP_PLAYGROUND_PORT=${MDCAP_NGINX_PLAYGROUND_PORT}

ENV_FILE=/root/gui/.env

cat <<EOF > $ENV_FILE
KEYCLOAK_REALM=${KEYCLOAK_REALM}
KEYCLOAK_SERVER=${KEYCLOAK_SERVER}
KEYCLOAK_CLIENT_ID=${KEYCLOAK_CLIENT_ID}
KEYCLOAK_REDIRECT_URI=${KEYCLOAK_REDIRECT_URI}
EOF

mkdir -p ${MDCAP_SSL_CERTS_DIR}
cp /.robin/scripts/certs/* ${MDCAP_SSL_CERTS_DIR}

VAR="$(ifconfig eth0 | grep inet6)"
if [ -z "$VAR" ]
then
	host=0.0.0.0
else
	host=0::0
fi

wetty --bypasshelmet --title "WeTTy" --forcessh --base "/plgconsole/" --host $host --port 3000 --sshhost ${MDCAP_PLAYGROUND_HOST} --sshport ${MDCAP_PLAYGROUND_PORT} --sslkey ${MDCAP_SSL_CERTS_DIR}/key.pem --sslcert ${MDCAP_SSL_CERTS_DIR}/cert.pem \
& node src/server/server.js --host $host --sslkey ${MDCAP_SSL_CERTS_DIR}/key.pem --sslcert ${MDCAP_SSL_CERTS_DIR}/cert.pem
