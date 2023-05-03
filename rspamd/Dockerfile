FROM alpine:3.17

ENV PATH="/container:${PATH}"

RUN apk update && \
    apk add rspamd rspamd-proxy rspamd-utils \
    rspamd-controller supervisor nginx && \
    rm -rf /var/cache/apk/* && mkdir /run/rspamd && mkdir /container

VOLUME ["/var/lib/rspamd"]

EXPOSE 11332/tcp
EXPOSE 80/tcp


COPY ./entrypoint.sh /container/entrypoint.sh

ENTRYPOINT ["/container/entrypoint.sh"]
CMD exec /usr/bin/supervisord -c /etc/supervisord/supervisord.conf
