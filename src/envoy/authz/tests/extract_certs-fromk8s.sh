#! /bin/sh
# Extract the cert from k8s secret so that it can be use for testing with Envoy.
# Usage: extracts_certs-fromk8s.sh secret-name namespace
#
set -x
kubectl get secrets -o yaml "${1}" --namespace="${2}" | grep -E '.pem:' | while read line;
do
  OUT=$(echo $line | awk -F:\  '{print$1}')
  echo $line | awk -F:\  '{print$NF}' | base64 -d -i - > "${1}"-$OUT
done
