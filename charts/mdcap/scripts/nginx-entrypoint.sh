#!/bin/sh -x

IPTYPE=$( nslookup $MDCAP_ENGINE_HOST | grep Server | awk '{ print $2 }')
https=1
if [ $https -eq "1" ]
then
    httpString="https"
else
    httpString="http"
fi

if [[ $(expr match "$IPTYPE" "\(.*:.*\)" ) ]];
then
    LISTEN_PORT="[::]:443 ssl"
    PL_LISTEN_PORT="[::]:22"
    NGX_EXPORTER_LISTEN_PORT="[::]:8080"
    MDCAP_ENGINE_HOST=${MDCAP_ENGINE_HOST}
else
    LISTEN_PORT="443 ssl"
    PL_LISTEN_PORT="22"
    NGX_EXPORTER_LISTEN_PORT="8080"
fi

MDCAP_DASHBOARD_URL="https://${MDCAP_DASHBOARD_HOST}:8000"
MDCAP_DASHBOARD_PLAYGROUND_URL="https://${MDCAP_DASHBOARD_PLAYGROUND_HOST}:3000"
MDCAP_ENGINE_URL="${httpString}://${MDCAP_ENGINE_HOST}:8000"
MDCAP_LOG_URL="${httpString}://${MDCAP_LOG_HOST}:8000"
MDCAP_EVTSRV_URL="${httpString}://${MDCAP_EVTSRV_HOST}:8000"
WORKER_PROCESSES="auto"
WORKER_CONNECTIONS="32768"
PROXY_CONNECT_TIMEOUT="3600"
PROXY_SEND_TIMEOUT="3600"
PROXY_READ_TIMEOUT="3600"
SEND_TIMEOUT="3600"
CLIENT_MAX_BODY_SIZE="100M"
WORKER_RLIMIT_NOFILE="65536"

apiversion=v1
api_url="api/${apiversion}"

cat << EOF > /etc/nginx/conf.d/default.conf
server {
    listen ${NGX_EXPORTER_LISTEN_PORT};

    location /stub_status {
        index index.html;
        stub_status on;
    }
EOF

if [ ! -z $MDCAP_CDN_HTTP_URL ]
then
cat << EOF >> /etc/nginx/conf.d/default.conf
location /artifact/${api_url} {
        client_max_body_size 20G;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_pass ${MDCAP_CDN_HTTP_URL};
    }
}
EOF
else
cat << EOF >> /etc/nginx/conf.d/default.conf
}
EOF
fi

cat << EOF >> /etc/nginx/conf.d/default.conf
server {
    listen  ${LISTEN_PORT};
    server_name localhost;
    ssl_certificate ${MDCAP_SSL_CERTS_DIR}/cert.pem;
    ssl_certificate_key ${MDCAP_SSL_CERTS_DIR}/key.pem;
    ssl_session_timeout 60m;
    keepalive_timeout   70;

    location /engine/${api_url} {
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_pass ${MDCAP_ENGINE_URL}/${api_url};
    }
    location /static {
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_pass ${MDCAP_ENGINE_URL}/static;
    }
    location /log/${api_url} {
        rewrite /log/${api_url}/(.*) /\$1  break;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_pass ${MDCAP_LOG_URL};
    }
    location /event-server/${api_url} {
        rewrite /log/${api_url}/(.*) /\$1  break;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_pass ${MDCAP_EVTSRV_URL};
    }
EOF

if [ ! -z $METRICS_GRAFANA_IP ]
then
METRICS_GRAFANA_URL="https://${METRICS_GRAFANA_IP}:3000"
cat << EOF >> /etc/nginx/conf.d/default.conf
    location /grafana {
        auth_basic "grafana";
        auth_basic_user_file "${METRICS_GRAFANA_DATA_DIR}/nginx/htpasswd";

        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_pass ${METRICS_GRAFANA_URL};
    }
EOF
fi

if [ ! -z $METRICS_IP ]
then
METRICS_URL="https://${METRICS_IP}:8428"
cat << EOF >> /etc/nginx/conf.d/default.conf
    location /vmetrics {
        auth_basic "grafana";
        auth_basic_user_file "${METRICS_GRAFANA_DATA_DIR}/nginx/htpasswd";

        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_pass ${METRICS_URL};
    }
EOF
fi

if [ ! -z $MDCAP_DASHBOARD_HOST ]
then
cat << EOF >> /etc/nginx/conf.d/default.conf
location / {
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_pass ${MDCAP_DASHBOARD_URL};
    }
EOF
fi

if [ ! -z $MDCAP_PLAYGROUND_HOST ]
then
cat << EOF >> /etc/nginx/conf.d/default.conf
    location ^~ /plgconsole {
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 43200000;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header Host \$http_host;
        proxy_set_header X-NginX-Proxy true;
        proxy_pass ${MDCAP_DASHBOARD_PLAYGROUND_URL};
    }
EOF
fi

if [ ! -z $MDCAP_CDN_URL ]
then
cat << EOF >> /etc/nginx/conf.d/default.conf
location /artifact/${api_url} {
        client_max_body_size 20G;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_pass ${MDCAP_CDN_URL};
    }
EOF
fi

cat << EOF >> /etc/nginx/conf.d/default.conf
}
EOF

cat << EOF > /etc/nginx/nginx.conf
user  nginx;
worker_processes  ${WORKER_PROCESSES};
worker_rlimit_nofile ${WORKER_RLIMIT_NOFILE};

error_log  /var/log/nginx/error.log warn;
pid        /var/run/nginx.pid;


events {
    worker_connections  ${WORKER_CONNECTIONS};
    multi_accept on;
    use epoll;
}


http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;
    client_max_body_size ${CLIENT_MAX_BODY_SIZE};

    log_format  main  '\$remote_addr - \$remote_user [\$time_local] "\$request" '
                      '\$status \$body_bytes_sent "\$http_referer" '
                      '"\$http_user_agent" "\$http_x_forwarded_for"';

    access_log  /var/log/nginx/access.log  main;
    proxy_connect_timeout ${PROXY_CONNECT_TIMEOUT};
    proxy_read_timeout ${PROXY_READ_TIMEOUT};
    proxy_send_timeout ${PROXY_SEND_TIMEOUT};
    send_timeout ${SEND_TIMEOUT};

    sendfile        on;
    #tcp_nopush     on;

    keepalive_timeout  65;

    #gzip  on;

    include /etc/nginx/conf.d/*.conf;
}
EOF


if [ ! -z $MDCAP_PLAYGROUND_HOST ]
then
cat << EOF >> /etc/nginx/nginx.conf
stream {
    server {
        listen ${PL_LISTEN_PORT};
        proxy_pass ${MDCAP_PLAYGROUND_HOST}:22;
    }
}
EOF
fi

exec "$@"

