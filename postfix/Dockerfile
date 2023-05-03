FROM debian:bullseye

ENV PATH="/container:${PATH}"
ENV DEBIAN_FRONTEND noninteractive

RUN apt-get -q -y update \
 && apt-get -q -y install --no-install-recommends runit procps nano \
    telnet net-tools postfix arj bzip2 cabextract cpio file openssl \
    gzip nomarch pax unzip zip libsasl2-modules sasl2-bin rsyslog \
 && apt-get -q -y clean \
 && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* \
 && head -n $(grep -n RULES /etc/rsyslog.conf | cut -d':' -f1) /etc/rsyslog.conf > /etc/rsyslog.conf.new \
 && mv /etc/rsyslog.conf.new /etc/rsyslog.conf \
 && echo '*.*        /dev/stdout' >> /etc/rsyslog.conf \
 && sed -i '/imklog/d' /etc/rsyslog.conf

# Postfix
RUN openssl dhparam -out /etc/postfix/dh1024.pem 1024 \
 && openssl dhparam -out /etc/postfix/dh512.pem 512 

COPY ./entrypoint.sh /container/entrypoint.sh

VOLUME ["/etc/postfix/tls", "/etc/postfix/config"]
HEALTHCHECK CMD ["/container/docker-healthcheck.sh"]
ENTRYPOINT ["entrypoint.sh"]

CMD [ "runsvdir","-P", "/etc/service" ]
