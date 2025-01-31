FROM python:3.13-alpine

# Copy the collector
ADD crowdstrike /opt/openbas-collector-crowdstrike/crowdstrike
WORKDIR /opt/openbas-collector-crowdstrike
ADD requirements.txt .

# Install Python modules
# hadolint ignore=DL3003
RUN apk update && apk upgrade && \
    apk --no-cache add git build-base libmagic libffi-dev libxslt libxslt-dev libxml2 libxml2-dev && \
    pip install --no-cache-dir -r requirements.txt && \
    apk del git build-base && \
    rm -rf /var/cache/apk/*

CMD ["python3", "-m", "crowdstrike.openbas_crowdstrike"]
