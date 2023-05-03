FROM alpine:3.17

RUN apk update && \
    apk add rspamd rspamd-proxy rspamd-utils \
    rspamd-controller supervisor nginx && \
    rm -rf /var/cache/apk/* && mkdir /run/rspamd

VOLUME ["/var/lib/rspamd"]

EXPOSE 11332/tcp
EXPOSE 80/tcp

COPY ./entrypoint.sh /

CMD ["/entrypoint.sh"]

