FROM debian:12-slim
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      postfix dovecot-imapd dovecot-pop3d openssl ca-certificates && rm -rf /var/lib/apt/lists/*
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh && useradd -m -s /bin/bash alice && echo "alice:lab-password" | chpasswd
ENTRYPOINT ["/entrypoint.sh"]
