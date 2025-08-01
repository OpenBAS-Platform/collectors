# OpenBAS CrowdStrike Endpoint Security Collector

The CrowdStrike Endpoint Security collector.

**Note**: Requires subscription to the CrowdStrike Falcon platform. The subscription
details dictate what data is actually available to the collector.

## Installation

### Docker Deployment

Build a Docker Image using the provided `Dockerfile`.

Example:

```shell
# Replace the IMAGE NAME with the appropriate value
docker build . -t [IMAGE NAME]
```

Make sure to replace the environment variables in `docker-compose.yml` with the appropriate configurations for your
environment. Then, start the docker container with the provided docker-compose.yml

```shell
docker compose up -d
# -d for detached
```

### Manual deployment

Get a local copy
```commandline
git checkout https://github.com/OpenBAS-Platform/collectors
cd ./collectors/crowdstrike
```
Install the environment:
**Production**:
```shell
# production environment
poetry install --extras prod
```

**Development** (note that you should also clone the [pyobas](OpenBAS-Platform/client-python) repository [according to
these instructions](../README.md#simultaneous-development-on-pyobas-and-a-collector))
```shell
# development environment
poetry install --extras dev
```

## Usage
```commandline
poetry run python -m crowdstrike.openbas_crowdstrike
```

## Configuration

The collector can be configured with the following variables:

| Config Parameter              | Docker env var              | Default                               | Description                                                                                   |
|-------------------------------|-----------------------------|---------------------------------------|-----------------------------------------------------------------------------------------------|
| `openbas`.`url`               | `OPENBAS_URL`               |                                       | The URL to the OpenBAS instance                                                               |
| `openbas`.`token`             | `OPENBAS_TOKEN`             |                                       | The auth token to the OpenBAS instance                                                        |
| `collector`.`id`              | `COLLECTOR_ID`              |                                       | Unique ID of the running collector instance                                                   |
| `collector`.`name`            | `COLLECTOR_NAME`            | `CrowdStrike Endpoint Security`       | Name of the collector (visible in UI)                                                         |
| `collector`.`type`            | `COLLECTOR_TYPE`            | `openbas_crowdstrike`                 | Type of the collector                                                                         |
| `collector`.`period`          | `COLLECTOR_PERIOD`          | 60                                    | Period for collection cycle (int, seconds)                                                    |
| `collector`.`log_level`       | `COLLECTOR_LOG_LEVEL`       | `warn`                                | Threshold for log severity in console output                                                  |
| `collector`.`platform`        | `COLLECTOR_PLATFORM`        | `EDR`                                 | Type of security platform this collector works for. One of: `EDR, XDR, SIEM, SOAR, NDR, ISPM` |
| `crowdstrike`.`api_base_url`  | `CROWDSTRIKE_API_BASE_URL`  | `https://api.us-2.crowdstrike.com`    | The base URL for the CrowdStrike APIs.                                                        |
| `crowdstrike`.`ui_base_url`   | `CROWDSTRIKE_UI_BASE_URL`   | `https://falcon.us-2.crowdstrike.com` | The base URL for the CrowdStrike UI you use to see your alerts.                               |
| `crowdstrike`.`client_id`     | `CROWDSTRIKE_CLIENT_ID`     |                                       | The CrowdStrike API client ID.                                                                |
| `crowdstrike`.`client_secret` | `CROWDSTRIKE_CLIENT_SECRET` |                                       | The CrowdStrike API client secret.                                                            |

**Note**: the Crowdstrike credentials must have been granted the following privilege for this to work: `Alerts: Read and Write`
(as per https://falcon.us-2.crowdstrike.com/documentation/page/d02475a5/converting-from-detects-api-to-alerts-api#s4c83596)

## Behavior

The collector retrieves recent alerts (last 45 minutes) from Crowdstrike and matches them with attacks executed
by OpenBAS agents to validate prevention and detection expectations.

## Development

### Run the tests
In a terminal:
```commandline
cd collectors/crowdstrike
poetry run python -m unittest
```