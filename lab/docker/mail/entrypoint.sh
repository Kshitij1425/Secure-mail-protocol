#!/bin/sh
# Test-only self-signed certificate; lab network is internal.
set -e
openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=mail.lab.test" \
  -keyout /etc/ssl/private/lab.key -out /etc/ssl/certs/lab.pem
postconf -e "smtpd_tls_cert_file=/etc/ssl/certs/lab.pem" "smtpd_tls_key_file=/etc/ssl/private/lab.key" \
  "smtpd_tls_security_level=may" "inet_interfaces=all" "mydestination=mail.lab.test, localhost"
postconf -M "submission/inet=submission inet n - y - - smtpd -o smtpd_tls_security_level=encrypt"
postconf -M "smtps/inet=smtps inet n - y - - smtpd -o smtpd_tls_wrappermode=yes"
cat > /etc/dovecot/conf.d/99-lab.conf <<CONF
ssl = yes
ssl_cert = </etc/ssl/certs/lab.pem
ssl_key = </etc/ssl/private/lab.key
disable_plaintext_auth = no
protocols = imap pop3
CONF
postfix start
exec dovecot -F
