#!/bin/bash

# checking that we have all variables
[[ -z ${AKAMAI_HOST} ]] && echo "Error: Akamai host variable is not set." && exit 1
[[ -z ${AKAMAI_CLIENT_TOKEN} ]] && echo "Error: Akamai client token variable is not set." && exit 1
[[ -z ${AKAMAI_CLIENT_SECRET} ]] && echo "Error: Akamai client secret variable is not set." && exit 1
[[ -z ${AKAMAI_ACCESS_TOKEN} ]] && echo "Error: Akamai access token variable is not set." && exit 1

# creating the config file
EDGE_FILE="${HOME}/.edgerc"
touch ${EDGE_FILE}
echo "[default]" >> ${EDGE_FILE}
echo "host = ${AKAMAI_HOST}" >> ${EDGE_FILE}
echo "client_token = ${AKAMAI_CLIENT_TOKEN}" >> ${EDGE_FILE}
echo "client_secret = ${AKAMAI_CLIENT_SECRET}" >> ${EDGE_FILE}
echo "access_token = ${AKAMAI_ACCESS_TOKEN}" >> ${EDGE_FILE}

# run the script
go run /go/src/akamai-ip-range/app.go