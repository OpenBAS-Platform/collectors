# OpenBAS Tanium Threat Response Collector

Table of Contents

- [OpenBAS Tanium Threat Response Collector](#openbas-tanium-threat-response-collector)
    - [Prerequisites](#prerequisites)
    - [Configuration variables](#configuration-variables)
        - [OpenBAS environment variables](#openbas-environment-variables)
        - [Base collector environment variables](#base-collector-environment-variables)
        - [Collector extra parameters environment variables](#collector-extra-parameters-environment-variables)
    - [Deployment](#deployment)
        - [Docker Deployment](#docker-deployment)
        - [Manual Deployment](#manual-deployment)
    - [Behavior](#behavior)

## Prerequisites

To use this collector, you need to have a Tanium instance and create an API token.

## Configuration variables

There are a number of configuration options, which are set either in `docker-compose.yml` (for Docker) or
in `config.yml` (for manual deployment).

### OpenBAS environment variables

Below are the parameters you'll need to set for OpenBAS:

| Parameter     | config.yml | Docker environment variable | Mandatory | Description                                          |
|---------------|------------|-----------------------------|-----------|------------------------------------------------------|
| OpenBAS URL   | url        | `OPENBAS_URL`               | Yes       | The URL of the OpenBAS platform.                     |
| OpenBAS Token | token      | `OPENBAS_TOKEN`             | Yes       | The default admin token set in the OpenBAS platform. |

### Base collector environment variables

Below are the parameters you'll need to set for running the collector properly:

| Parameter        | config.yml | Docker environment variable | Default | Mandatory | Description                                                                            |
|------------------|------------|-----------------------------|---------|-----------|----------------------------------------------------------------------------------------|
| Collector ID     | id         | `COLLECTOR_ID`              | /       | Yes       | A unique `UUIDv4` identifier for this collector instance.                              |
| Collector Name   | name       | `COLLECTOR_NAME`            |         | Yes       | Name of the collector.                                                                 |
| Collector Period | period     | `COLLECTOR_PERIOD`          |         | Yes       | The time interval at which your collector will run (int, seconds).                     |
| Log Level        | log_level  | `COLLECTOR_LOG_LEVEL`       | info    | Yes       | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`. |

### Collector extra parameters environment variables

Below are the parameters you'll need to set for the collector:

| Parameter          | config.yml         | Docker environment variable | Default | Mandatory | Description                          |
|--------------------|--------------------|-----------------------------|---------|-----------|--------------------------------------|
| Tanium URL         | tanium_url         | TANIUM_URL                  |         | Yes       | URL of your Tanium instance.         |
| Tanium URL Console | tanium_url_console | TANIUM_URL_CONSOLE          |         | Yes       | URL of your Tanium console instance. |
| Tanium API Token   | tanium_token       | TANIUM_TOKEN                |         | Yes       | API Token.                           |

## Deployment

### Docker Deployment

Build a Docker Image using the provided `Dockerfile`.

Example:

```shell
# Replace the IMAGE NAME with the appropriate value
docker build . -t [IMAGE NAME]:latest
```

Make sure to replace the environment variables in `docker-compose.yml` with the appropriate configurations for your
environment. Then, start the docker container with the provided docker-compose.yml

```shell
docker compose up -d
# -d for detached
```

### Manual Deployment

Create a file `config.yml` based on the provided `config.yml.sample`.

Replace the configuration variables with the appropriate configurations for
you environment.

Install the required python dependencies (preferably in a virtual environment):

```shell
poetry install
```

Then, start the collector:

```shell
poetry run python -m tanium_threat_response.openbas_tanium_threat_response
```

## Behavior

The collector retrieves recent alerts (last 45 minutes) from Tanium Threat Response d matches them with attacks executed
by OpenBAS agents to validate prevention and detection expectations.

The collector identifies matches using the parent process name. OpenBAS attacks are
recognized by the parent process name format: `openbas-implant-INJECT_ID.exe`.
