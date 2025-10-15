FROM openresty/openresty:1.21.4.2-alpine

RUN apk add --no-cache inotify-tools openssl

RUN mkdir -p /app/lua
COPY lua /app/lua

COPY --chmod=755 openresty-start.sh /openresty-start.sh

ENTRYPOINT ["/openresty-start.sh"]
