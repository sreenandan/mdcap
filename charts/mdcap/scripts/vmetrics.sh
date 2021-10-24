#!/bin/sh

mkdir -p /victoria-metrics-data/victoria_metrics

FILE=/victoria-metrics-data/victoria_metrics/vm.yaml

echo '
global:
  evaluation_interval: 10s

scrape_configs:

  # define local scrape interval
  - job_name: mdcap-engine
    scrape_interval: 60s
    scrape_timeout: 60s
    metrics_path: /api/v1/metrics
    scheme: https
    static_configs:
      - targets:
        - "MDCAP_NAME-engine.MDCAP_NS.svc.cluster.local:8000"
    tls_config:
      insecure_skip_verify: true

  - job_name: mdcap-dashboard
    scrape_interval: 60s
    scrape_timeout: 60s
    metrics_path: /metrics
    scheme: https
    static_configs:
      - targets:
        - "MDCAP_NAME-dashboard.MDCAP_NS.svc.cluster.local:8000"
    tls_config:
      insecure_skip_verify: true

  - job_name: mdcap-logstore
    scrape_interval: 60s
    scrape_timeout: 60s
    metrics_path: /metrics
    scheme: https
    static_configs:
      - targets:
        - "MDCAP_NAME-logstore.MDCAP_NS.svc.cluster.local:8000"
    tls_config:
      insecure_skip_verify: true

  - job_name: mdcap-nginx
    scrape_interval: 60s
    scrape_timeout: 60s
    metrics_path: /metrics
    scheme: http
    static_configs:
      - targets:
        - "MDCAP_NAME-nginx-np-0.MDCAP_NS.svc.cluster.local:9113"

  - job_name: mdcap-grafana
    scrape_interval: 60s
    scrape_timeout: 60s
    metrics_path: /metrics
    scheme: https
    static_configs:
      - targets:
        - "MDCAP_NAME-grafana.MDCAP_NS.svc.cluster.local:3000"
    tls_config:
      insecure_skip_verify: true

  - job_name: mdcap-vmetrics
    scrape_interval: 60s
    scrape_timeout: 60s
    metrics_path: /metrics
    scheme: https
    static_configs:
      - targets:
        - "MDCAP_NAME-vmetrics.MDCAP_NS.svc.cluster.local:8428"
    tls_config:
      insecure_skip_verify: true

  # event server
  - job_name: mdcap-eventserver
    scrape_interval: 60s
    scrape_timeout: 60s
    metrics_path: /metrics
    scheme: https
    static_configs:
      - targets:
        - "MDCAP_NAME-eventserver.MDCAP_NS.svc.cluster.local:8000"
    tls_config:
      insecure_skip_verify: true

  # artifactory
  - job_name: mdcap-artifactory
    scrape_interval: 60s
    scrape_timeout: 60s
    metrics_path: /metrics
    scheme: https
    static_configs:
      - targets:
        - "MDCAP_NAME-artifactory.MDCAP_NS.svc.cluster.local:8443"
    tls_config:
      insecure_skip_verify: true
  # playground

  # How to get the scrape target for mdcapds ?
  - job_name: mdcapds-etcd
    scrape_interval: 60s
    scrape_timeout: 60s
    metrics_path: /metrics
    scheme: https
    static_configs:
      - targets:
        - "MDCAPDS_SITE1_IP:ETCD_DATA_PORT_1"
        - "MDCAPDS_SITE1_IP:ETCD_DATA_PORT_2"
        - "MDCAPDS_SITE1_IP:ETCD_DATA_PORT_3"
    tls_config:
      insecure_skip_verify: true

  - job_name: mdcapds-postgresql
    scrape_interval: 60s
    scrape_timeout: 60s
    metrics_path: /metrics
    static_configs:
      - targets:
        - "MDCAPDS_SITE1_IP:9187"

  - job_name: mdcapds-patroni
    scrape_interval: 60s
    scrape_timeout: 60s
    metrics_path: /metrics
    static_configs:
      - targets:
        - "MDCAPDS_SITE1_IP:9547"
        - "MDCAPDS_SITE1_IP:9548"
        - "MDCAPDS_SITE1_IP:9549"

' > ${FILE}

# replace placeholders
sed -i "s/MDCAP_NAME/${MDCAP_NAME}/g" ${FILE}
sed -i "s/MDCAP_NS/${MDCAP_NS}/g" ${FILE}
sed -i "s/MDCAPDS_SITE1_IP/${MDCAPDS_SITE1_IP}/g" ${FILE}
sed -i "s/ETCD_DATA_PORT_1/${ETCD_DATA_PORT_1}/g" ${FILE}
sed -i "s/ETCD_DATA_PORT_2/$((2 + ETCD_DATA_PORT_1))/g" ${FILE}
sed -i "s/ETCD_DATA_PORT_3/$((4 + ETCD_DATA_PORT_1))/g" ${FILE}

if ifconfig | grep -q inet6 ; then
    /victoria-metrics-prod -enableTCP6 -retentionPeriod ${METRICS_RETENTION_PERIOD} -tls -tlsCertFile /etc/mdcap/certs/cert.pem -tlsKeyFile /etc/mdcap/certs/key.pem -promscrape.config ${FILE}
else
    /victoria-metrics-prod -retentionPeriod ${METRICS_RETENTION_PERIOD} -tls -tlsCertFile /etc/mdcap/certs/cert.pem -tlsKeyFile /etc/mdcap/certs/key.pem -promscrape.config ${FILE}
fi
