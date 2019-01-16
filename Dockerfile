FROM golang:1.11-alpine3.8
RUN apk add curl bash jq git --no-cache

RUN mkdir -p /go/src/akamai-ip-range
WORKDIR /go/src/akamai-ip-range

COPY app.go /go/src/akamai-ip-range/app.go
COPY init.sh /go/src/akamai-ip-range/init.sh
RUN go get -d -v .

# The following variables must be supplied in order to use Akamai's API:
#
# AKAMAI_HOST
# AKAMAI_CLIENT_TOKEN
# AKAMAI_CLIENT_SECRET
# AKAMAI_ACCESS_TOKEN
#

# These variables will rewrite defaults in the app.go:
#
# AKMGOAPP_SECURITY_GROUPS (*)
# AKMGOAPP_MAP_ID (*)
#
# AKMGOAPP_LOG_LEVEL
# AKMGOAPP_SG_RULE_DESCRIPTION
# AKMGOAPP_MAP_ADDR
# AKMGOAPP_AWS_REGION
# AKMGOAPP_ACK_MAP
#
# (*) - required. 

CMD ["/go/src/akamai-ip-range/init.sh"]