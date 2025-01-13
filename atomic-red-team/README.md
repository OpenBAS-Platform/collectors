# OpenBAS Atomic Red Team Collector

Table of Contents

- [OpenBAS Atomic Red Team Collector](#openbas-atomic-red-team-collector)
    - [Configuration variables](#configuration-variables)
        - [OpenBAS environment variables](#openbas-environment-variables)
        - [Base collector environment variables](#base-collector-environment-variables)
    - [Deployment](#deployment)
        - [Docker Deployment](#docker-deployment)
        - [Manual Deployment](#manual-deployment)
    - [Behavior](#behavior)

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

Below are the parameters you'll need to set for running the connector properly:

| Parameter        | config.yml | Docker environment variable | Default | Mandatory | Description                                                                            |
|------------------|------------|-----------------------------|---------|-----------|----------------------------------------------------------------------------------------|
| Collector ID     | id         | `COLLECTOR_ID`              | /       | Yes       | A unique `UUIDv4` identifier for this collector instance.                              |
| Collector Name   | name       | `COLLECTOR_NAME`            |         | Yes       | Name of the collector.                                                                 |
| Collector Period | period     | `COLLECTOR_PERIOD`          |         | Yes       | The time interval at which your collector will run.                                    |
| Log Level        | log_level  | `COLLECTOR_LOG_LEVEL`       | info    | Yes       | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`. |

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
pip3 install -r requirements.txt
```

Then, start the connector:

```shell
python3 openbas_microsoft_defender.py
```

## Behavior

This collector retrieves the Atomic Red Team GitHub repository to extract payloads and import them into your OpenBAS
instance.
