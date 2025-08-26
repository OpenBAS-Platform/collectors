FROM python:3.11-alpine
ENV PYTHONUNBUFFERED=1

RUN apk update && apk upgrade && apk add --no-cache gcc g++ musl-dev python3-dev libffi-dev openssl-dev

RUN mkdir /opt/openbas-microsoft-azure-collector
WORKDIR /opt/openbas-microsoft-azure-collector

ENV PATH="${PATH}:/root/.local/bin"
RUN pip install --user --upgrade pip setuptools wheel
RUN pip install --user poetry

# Copy files
COPY . ./
RUN cd /opt/openbas-microsoft-azure-collector && poetry install --with prod --extras prod

# Expose and entrypoint
COPY microsoft_azure /opt/openbas-microsoft-azure-collector
WORKDIR /opt/openbas-microsoft-azure-collector
ENV PYTHONPATH=/opt/openbas-microsoft-azure-collector
ENTRYPOINT ["poetry", "run", "python3", "openbas_microsoft_azure.py"]
