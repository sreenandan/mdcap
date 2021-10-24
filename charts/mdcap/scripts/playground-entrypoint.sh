#!/bin/bash

cd /usr/bin
ln -s /.robin/scripts/app/mdcapcli/mdcap.py mdcap
cd /.robin/scripts/app


if [[ $(expr match "$MDCAP_ENGINE_HOST" "\(.*:.*\)" ) ]];
then
    MDCAP_ENGINE_HOST='['${MDCAP_ENGINE_HOST}']'
fi

# MDCAP_DEFAULT_CONTEXT uses internal engine cluster ip dns name
# If nginx ip and port is required, user should use mdcap set-context command

echo "export MDCAP_LOG_HOST=\"${MDCAP_LOG_HOST}\"" >> /etc/profile
echo "export MDCAP_ENGINE_HOST=\"${MDCAP_ENGINE_HOST}\"" >> /etc/profile
echo "export LANG=en_US.UTF-8" >> /etc/profile
echo "export MDCAP_ARTIFACTORY_HOST=\"${MDCAP_ARTIFACTORY_HOST}\"" >> /etc/profile
echo "export MDCAP_EVTSRV_HOST=\"${MDCAP_LOG_HOST}\"" >> /etc/profile

# https is default
https=1
echo "export HTTPS=\"true\"" >> /etc/profile
echo "export MDCAP_LOG_URL=\"https://${MDCAP_LOG_HOST}:8000\"" >> /etc/profile
echo "export MDCAP_ENGINE_URL=\"https://${MDCAP_ENGINE_HOST}:8000\"" >> /etc/profile
echo "export MDCAP_ARTIFACTORY_URL=\"https://${MDCAP_ARTIFACTORY_HOST}:8443\"" >> /etc/profile
echo "export MDCAP_EVTSRV_URL=\"https://${MDCAP_EVTSRV_HOST}:8000\"" >> /etc/profile
echo "export MDCAP_DEFAULT_CONTEXT=${MDCAP_DEFAULT_CONTEXT}" >> /etc/profile
export MDCAP_LOG_URL="https://${MDCAP_LOG_HOST}:8000"
export MDCAP_ENGINE_URL="https://${MDCAP_ENGINE_HOST}:8000"
export MDCAP_ARTIFACTORY_URL="https://${MDCAP_ARTIFACTORY_HOST}:8443"
export MDCAP_EVTSRV_URL="https://${MDCAP_EVTSRV_HOST}:8000"
export MDCAP_DEFAULT_CONTEXT="${MDCAP_DEFAULT_CONTEXT}"

echo "source /etc/profile" >> ~/.bashrc

if [[ ! -e /etc/ssh/ssh_host_rsa_key ]]; then
    ssh-keygen -q -t rsa -N '' -f /etc/ssh/ssh_host_rsa_key
fi

cd /runner
tar -xf node_exporter-1.0.1.linux-amd64.tar.gz && \
chmod +x node_exporter-1.0.1.linux-amd64/node_exporter && \
node_exporter-1.0.1.linux-amd64/node_exporter &
cd -

mkdir -p  ${MDCAP_SSL_CERTS_DIR}
cp /.robin/scripts/certs/* ${MDCAP_SSL_CERTS_DIR}

file=/etc/ssh/sshd_config
sed -i "/#UsePrivilegeSeparation/a UsePrivilegeSeparation no" $file
MDCAP_APPNAME=$(hostname | cut -d'-' -f1)
mdcap server-context set default "${MDCAP_DEFAULT_CONTEXT}" -d
/usr/sbin/sshd -D
