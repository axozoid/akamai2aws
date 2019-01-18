FROM golang:1.11-alpine3.8 as builder
RUN apk add git --no-cache

RUN mkdir -p /go/src/akamai-ip-range
WORKDIR /go/src/akamai-ip-range

COPY app.go /go/src/akamai-ip-range/app.go
RUN go get -d -v .
RUN CGO_ENABLED=0 go build -o /go/src/akamai-ip-range/akamai2aws /go/src/akamai-ip-range/app.go

# final image
FROM alpine:3.8
RUN apk add bash --no-cache
RUN mkdir /app
COPY --from=builder /go/src/akamai-ip-range/akamai2aws /app/akamai2aws
COPY init.sh /app/init.sh

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

CMD ["/app/init.sh"]