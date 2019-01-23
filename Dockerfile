FROM golang:1.11-alpine3.8 as builder
ARG GIT_VERSION="2.18.1-r0"
RUN apk add git=${GIT_VERSION} --no-cache

RUN mkdir -p /go/src/akamai-ip-range
WORKDIR /go/src/akamai-ip-range
COPY app.go /go/src/akamai-ip-range/app.go
RUN go get -d -v .
ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOARCH=amd64
RUN go build -o /go/src/akamai-ip-range/akamai2aws /go/src/akamai-ip-range/app.go

# final image
FROM alpine:3.8
ARG CA_CERTS_VERSION="20171114-r3"
ARG BASH_VERSION="4.4.19-r1"
RUN apk add bash=${BASH_VERSION} ca-certificates=${CA_CERTS_VERSION} --no-cache

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

ENTRYPOINT ["/app/init.sh"]