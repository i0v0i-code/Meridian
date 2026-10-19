# Trusted PROXY protocol ingress (custom fork)

This fork adds optional HAProxy PROXY protocol v1/v2 support to Meridian's
**controller panel/shared-host listener**, before TLS termination. The base is
upstream `v1.11.3`. Dedicated site listeners and edge Agent listeners are unchanged.

## Enable

Set `PANEL_PROXY_PROTOCOL_TRUSTED_CIDRS` to the immediate TCP peer addresses that
may supply PROXY headers. Empty/unset disables this feature completely.

```yaml
services:
  meridian:
    image: bolocolo/meridian:v1.11.3-proxyproto.1
    ports:
      - "127.0.0.1:18443:443"
    environment:
      # Example only: use the actual bridge gateway seen by this container.
      PANEL_PROXY_PROTOCOL_TRUSTED_CIDRS: "172.19.0.1/32"
```

Keep the existing database, certificates and panel listening port. If the
container network is recreated with a different subnet, update the trusted
gateway address. Publish the backend only on loopback or otherwise restrict
network access to the trusted edge. A CIDR allowlist is not authentication:
any process able to originate connections from an allowed address can assert
client addresses. Do not trust the entire Internet or a shared Docker subnet.

Configure the existing HAProxy backend:

```haproxy
backend meridian_tls
    server meridian 127.0.0.1:18443 check send-proxy-v2
```

HAProxy still routes by SNI and leaves TLS encrypted. Meridian continues to
manage certificates and host-based sites. Adding domains requires no gateway
changes. Original IPv4 and IPv6 addresses are supported even when the backend
TCP connection itself uses IPv4.

## Trust and compatibility

- Trusted peers **must** send a valid PROXY header; missing/malformed headers
  fail closed. The header read deadline is five seconds.
- Other peers may use direct HTTP/TLS, but PROXY headers from them are rejected.
  This preserves the container's direct loopback healthcheck without trusting
  it to assert arbitrary addresses. Do not include loopback in the allowlist
  when using the unmodified direct healthcheck.
- The transport's `RemoteAddr` becomes the supplied source address. Existing
  request logs, client-based limiting and upstream IP headers therefore use it.
- This setting is separate from `TRUSTED_PROXY_CIDRS`. Do not populate that HTTP
  header trust list just to enable PROXY protocol. Visitor-supplied `X-Real-IP`
  and `X-Forwarded-For` remain untrusted unless explicitly configured otherwise.
- Source IP means the client that connected to HAProxy. A CDN in front of
  HAProxy still appears as the source unless separately integrated.

## Build and test

```sh
go test ./...
go vet ./...
docker build --build-arg VERSION=v1.11.3 \
  --build-arg DISTRIBUTION_VERSION=v1.11.3-proxyproto.1 \
  -t bolocolo/meridian:v1.11.3-proxyproto.1 .
```

Keep the internal `VERSION` at the upstream release. Meridian uses it to select
official Agent release manifests; a custom suffix switches it to development
Agent distribution and can trigger unwanted Agent binary replacements. The
custom release is identified by the image tag, OCI version/revision labels and
Git tag, while the application/Agent protocol version remains `v1.11.3`.

The transport integration tests cover v1/v2, IPv4/IPv6, TLS, request-log and
upstream-header identity, visitor-header spoofing, required/missing headers,
untrusted senders, direct healthchecks, disabled mode and incomplete-header
timeouts. Production acceptance should also compare a request from a known
external IP with the resulting Meridian request log.

Rollback both sides together: restore the previous image/environment **and**
remove `send-proxy-v2`. An upstream image cannot parse PROXY headers.
