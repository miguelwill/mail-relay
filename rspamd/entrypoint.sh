#!/bin/sh

if ! [ -f /etc/rspamd/local.d/dkim_signing.conf ]; then
  cat <<EOFDK > /etc/rspamd/local.d/dkim_signing.conf
enabled = false;
EOFDK
fi
if ! [ -f /etc/rspamd/local.d/logging.inc ]; then
  cat <<EOFDK > /etc/rspamd/local.d/logging.inc
type = "console";
level = "notice";
EOFDK
fi
if ! [ -f /etc/rspamd/local.d/milter_headers.conf ]; then
  cat <<EOFDK > /etc/rspamd/local.d/milter_headers.conf
use = ["authentication-results", "x-spam-status"];
authenticated_headers = ["authentication-results"];
EOFDK
fi
if ! [ -f /etc/rspamd/local.d/redis.conf ] && ! [ -z $REDIS_HOST ]; then
  cat <<EOFDK > /etc/rspamd/local.d/redis.conf
servers = "$REDIS_HOST";
EOFDK
fi
if ! [ -f /etc/rspamd/local.d/worker-normal.inc ]; then
  cat <<EOFDK > /etc/rspamd/local.d/worker-normal.inc
enabled = false;
EOFDK
fi
if ! [ -f /etc/rspamd/local.d/worker-controller.inc ]; then
  cat <<EOFDK > /etc/rspamd/local.d/worker-controller.inc
type = "controller";
bind_socket = "*:11334";
EOFDK
  if ! [ -z $WEB_GUI_PASSWORD_HASH ]; then
    cat <<EOFDK >> /etc/rspamd/local.d/worker-controller.inc
password = "$WEB_GUI_PASSWORD_HASH";
enable_password = "$WEB_GUI_PASSWORD_HASH";
EOFDK
  fi
fi
if ! [ -f /etc/rspamd/local.d/worker-proxy.inc ]; then
  cat <<EOFDK > /etc/rspamd/local.d/worker-proxy.inc
milter = yes;
bind_socket = "0.0.0.0:11332";
timeout = 120s;
upstream "local" {
  default = yes;
  self_scan = yes;
}
count = 4;
max_retries = 5;
discard_on_reject = true;
quarantine_on_reject = false;
spam_header = "X-Spam";
reject_message = "Spam message rejected";
EOFDK
fi
if [ -z $CLAMAV_HOST ]; then
  rm -f /etc/rspamd/local.d/antivirus.conf
else
 cat <<EOFAV > /etc/rspamd/local.d/antivirus.conf
enabled = true

clamav {
  action = "reject";
  scan_mime_parts = false;
  symbol = "CLAM_VIRUS";
  type = "clamav";
  servers = "$CLAMAV_HOST:3310";
}

EOFAV
fi
if ! [ -f /etc/rspamd/local.d/phishing.conf ] && ! [ -z $IS_ENABLE_PHISHING ]; then
  cat <<EOFPH > /etc/rspamd/local.d/phishing.conf
openphish_enabled = true;
phishtank_enabled = true;
EOFPH
fi

cat <<EOFNG > /etc/nginx/nginx.conf
worker_processes  2;
user nginx nginx;

pid        /var/run/nginx.pid;

error_log /dev/stdout info;

events {
        worker_connections 8192;
        use epoll;
}

http {
    include       mime.types;
    default_type  text/plain;

    sendfile  on;
    tcp_nopush   on;
    tcp_nodelay on;

    gzip  on;

    server {
        access_log /dev/stdout;

        location / {
            alias /usr/share/rspamd/www/;
            try_files \$uri @proxy;
        }
        location @proxy {
                proxy_pass  http://127.0.0.1:11334;
                proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
                proxy_set_header Host \$http_host;
        }
        server_tokens off;
    }
}
EOFNG

mkdir /etc/supervisord
cat <<EOFSV > /etc/supervisord/supervisord.conf
[supervisord]
nodaemon=true
user=root

[program:rspamd]
command=/usr/sbin/rspamd -f -u rspamd -g rspamd
stdout_logfile=/dev/stdout
stdout_logfile_maxbytes=0
stderr_logfile=/dev/stderr
stderr_logfile_maxbytes=0

[program:nginx]
command=/usr/sbin/nginx -g 'daemon off;'
stdout_logfile=/dev/stdout
stdout_logfile_maxbytes=0
stderr_logfile=/dev/stderr
stderr_logfile_maxbytes=0
EOFSV

/usr/bin/supervisord -c /etc/supervisord/supervisord.conf
