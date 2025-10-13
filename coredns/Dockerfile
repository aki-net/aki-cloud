FROM coredns/coredns:1.11.1 AS upstream

FROM alpine:3.20
COPY --from=upstream /coredns /coredns
COPY --chmod=755 coredns-start.sh /coredns-start.sh

ENTRYPOINT ["/bin/sh", "/coredns-start.sh"]
