#!/bin/sh
set -x
APISERVER=https://kubernetes.default.svc
# Path to ServiceAccount token
SERVICEACCOUNT=/var/run/secrets/kubernetes.io/serviceaccount
# Read this Pod's namespace
NAMESPACE=$(cat ${SERVICEACCOUNT}/namespace)
# Read the ServiceAccount bearer token
TOKEN=$(cat ${SERVICEACCOUNT}/token)
# Reference the internal certificate authority (CA)
CACERT=${SERVICEACCOUNT}/ca.crt

# if we need to debug anything to uninstall hook we can edit the UNINSTALLHOOK_DELAY
# value in config map: <releasename>-uninstallhook-env and then initiate a uninstall.
# the predelete hook will wait for these many seconds before initiating the uninstall
if [ ! -z "$ADD_DELAY_SEC_BEFORE_UNINSTALL" ]; then
    echo "$ADD_DELAY_SEC_BEFORE_UNINSTALL Seconds to terminate"
    sleep $ADD_DELAY_SEC_BEFORE_UNINSTALL
    echo "Terminating..."
fi

for sts in $(curl --cacert ${CACERT} --header "Authorization: Bearer ${TOKEN}" -X GET "${APISERVER}/apis/apps/v1/namespaces/$NAMESPACE/statefulsets?labelSelector=release%3D${MDCAP_RELEASE_NAME}" | jq -r '.items | .[] | .metadata.name');
do
	echo "Terminating Statefulset: "
	curl --fail --cacert ${CACERT} --header "Authorization: Bearer ${TOKEN}" -X DELETE ${APISERVER}/apis/apps/v1/namespaces/$NAMESPACE/statefulsets/$sts || echo "Failed to delete Statefulset: $sts"
done
exit 0
