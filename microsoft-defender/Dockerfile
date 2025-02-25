FROM python:3.13-alpine

# Copy the collector
COPY microsoft-defender /opt/openbas-collector-microsoft-defender

# Install Python modules
# hadolint ignore=DL3003
RUN apk update && apk upgrade && \
    apk --no-cache add git build-base libmagic libffi-dev libxslt libxslt-dev libxml2 libxml2-dev rust cargo && \
    cd /opt/openbas-collector-microsoft-defender && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base rust cargo libffi-dev libxslt-dev libxml2-dev

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
