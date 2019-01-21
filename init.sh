#!/bin/bash

# checking that we have all variables
[[ -z "${AKAMAI_HOST}" ]] && echo "Error: Akamai host variable is not set." && exit 1
[[ -z "${AKAMAI_CLIENT_TOKEN}" ]] && echo "Error: Akamai client token variable is not set." && exit 1
[[ -z "${AKAMAI_CLIENT_SECRET}" ]] && echo "Error: Akamai client secret variable is not set." && exit 1
[[ -z "${AKAMAI_ACCESS_TOKEN}" ]] && echo "Error: Akamai access token variable is not set." && exit 1

# run the script
/app/akamai2aws