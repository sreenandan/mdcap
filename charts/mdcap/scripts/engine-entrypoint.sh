#!/bin/sh

set -x

MDCAP_INI="/etc/engine.runtime.config"
APPDIR=/mdcap/scripts/app
export PATH=/mdcap/scripts/app:$PATH


# Create mdcap binary link
if [ ! -f /usr/bin/mdcap ];then
    ln -s ${APPDIR}/mdcapcli/mdcap.py /usr/bin/mdcap
fi

# Set the IP addr
RORC_HOST=0.0.0.0
if hostname -i | grep -q ':';then
    RORC_HOST=0::0
    MDCAP_ENGINE_HOST='['${MDCAP_ENGINE_HOST}']'
fi

# if ipv6 is set, we assume setup is ipv6
if ifconfig | grep -q inet6 ; then
    RORC_HOST=0::0
    MDCAP_ENGINE_HOST='['${MDCAP_ENGINE_HOST}']'
fi

# Start adding to runtime config which will overwrite config
echo "RORC_HOST=\"${RORC_HOST}\"" > $MDCAP_INI
echo "MDCAP_SCRIPTS_PATH=\"${MDCAP_SCRIPTS_PATH}\"" >> $MDCAP_INI
echo "APPDIR=\"${APPDIR}\"" >> $MDCAP_INI

mkdir -p /victoria-metrics-data/tokens
mkdir -p ${MDCAP_SCRIPTS_PATH}

https=1
file=${MDCAP_INI}
if [ $https -eq "1" ]
then
    echo "MDCAP_ENGINE_URL=\"https://${MDCAP_ENGINE_HOST}:8000\"" >> $MDCAP_INI
    echo "MDCAP_LOG_URL=\"https://${MDCAP_LOG_HOST}:8000\"" >> $MDCAP_INI
    echo "HTTPS=\"true\"" >> $MDCAP_INI
else
    echo "MDCAP_ENGINE_URL=\"http://${MDCAP_ENGINE_HOST}:8000\"" >> $MDCAP_INI
    echo "MDCAP_LOG_URL=\"http://${MDCAP_LOG_HOST}:8000\"" >> $MDCAP_INI
    echo "HTTPS=\"false\"" >> $MDCAP_INI
fi


if [ ! -d $MDCAP_SSL_CERTS_DIR ];then
    mkdir -p $MDCAP_SSL_CERTS_DIR
    cd $MDCAP_SSL_CERTS_DIR
    # openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj '/CN=localhost'
    cp /mdcap/scripts/certs/* ${MDCAP_SSL_CERTS_DIR}
    cd /mdcap/scripts/app
fi

if [ ! -d $METRICS_GRAFANA_IP ];then
    # create the htpasswd file, which is basic auth for
    # login into grafana through nginx in /grafana-data
    # as this will be mounted inside nginx and grafana pods as a pvc
    # this will be used to do rbac in future.
    # NOTE - maybe mounting a single volume into 3 pods is not recommended,
    # not using k8s secrets coz laziness :)
    user=${METRICS_GRAFANA_USER}
    passwd=${METRICS_GRAFANA_PASSWORD}
    mkdir -p ${METRICS_GRAFANA_DATA_DIR}/nginx/
    htpasswd -cb ${METRICS_GRAFANA_DATA_DIR}/nginx/htpasswd $user $passwd

fi

# Load the environment
cat /etc/mdcap/config/engine.config | grep -v "^$" | grep -v "^#" | awk '{print "export " $0}' > /tmp/mdcap.env
cat $MDCAP_INI | grep -v "^$" | grep -v "^#" | awk '{print "export " $0}' >> /tmp/mdcap.env

. /tmp/mdcap.env

export MDCAP_INI=${MDCAP_INI}
cd $APPDIR

sed -i '111 i \        return html(f"{self.text}", status=self.status)' /usr/local/lib/python3.7/site-packages/sanic/errorpages.py
sed -i '123 i \        return html(f"{self.text}", status=self.status, headers=self.headers)' /usr/local/lib/python3.7/site-packages/sanic/errorpages.py

tar xf helm.tar.gz -C /tmp
cp /tmp/linux-amd64/helm /usr/local/bin/helm

MDCAP_APPNAME=$(hostname | cut -d'-' -f1)
mdcap server-context set default "${MDCAP_DEFAULT_CONTEXT}" -d
python ./trigger.py &
python ./app.py
