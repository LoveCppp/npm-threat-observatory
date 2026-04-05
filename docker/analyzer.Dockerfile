FROM node:20-bookworm-slim

RUN apt-get update \
  && apt-get install -y --no-install-recommends bash ca-certificates curl git jq procps python3 \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

COPY app /opt/npm-security-check/app
COPY samples /opt/npm-security-check/samples
COPY scripts /opt/npm-security-check/scripts

RUN chmod +x /opt/npm-security-check/scripts/*.sh \
  && mkdir -p /opt/npm-security-check/bin \
  && mkdir -p /workspace /tmp/npm-security-home /tmp/npm-security-check \
  && chown -R node:node /workspace /tmp/npm-security-home /tmp/npm-security-check /opt/npm-security-check \
  && ln -sf /opt/npm-security-check/scripts/portable-wrapper.sh /opt/npm-security-check/bin/curl \
  && ln -sf /opt/npm-security-check/scripts/portable-wrapper.sh /opt/npm-security-check/bin/wget \
  && ln -sf /opt/npm-security-check/scripts/portable-wrapper.sh /opt/npm-security-check/bin/chmod \
  && ln -sf /opt/npm-security-check/scripts/portable-wrapper.sh /opt/npm-security-check/bin/cat \
  && ln -sf /opt/npm-security-check/scripts/portable-wrapper.sh /opt/npm-security-check/bin/cp \
  && ln -sf /opt/npm-security-check/scripts/portable-wrapper.sh /opt/npm-security-check/bin/grep \
  && ln -sf /opt/npm-security-check/scripts/portable-wrapper.sh /opt/npm-security-check/bin/sed

USER node

CMD ["/bin/bash"]
