# OpenBAS NVD NIST CVE collector

The NVD NIST CVE collector is a standalone Python process that collects data from the NVD (National Vulnerability Database).

### CVE and CVSS base score V3.1

CVEs are assigned a criticality score (CVSS) making it possible to prioritize vulnerabilities and thus prioritize IS security projects.  
As of July 13th, 2022, the NVD will no longer generate new information for CVSS v2.  
Existing CVSS V2 information will remain in the database, but the NVD will no longer actively populate CVSS V2 for new CVEs.  
CVSS V3.1 was released in June 2019, thus most CVE published before 2019 do not include the `cvssMetricV31` object. The exception are CVE published before 2019 that were later reanalyzed or modified.  
These CVE may have been updated to include CVSS V3.1 information. If the CVE was updated in this way, the API response would include this optional information.

This collector **will import all CVE with CVSS V3.1 base score**.

## Requirements

- OpenBAS Platform version 1.19 or higher  
- An **API Key for accessing NVD** – required to use the NVD CVE API.  
  👉 You can request a free API key here: [https://nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key)  
  Once you’ve submitted the request form, your API key will be sent to your email address. Keep it safe and include it in your configuration (see below).

## Installation

Get a local copy:

```bash
git clone https://github.com/OpenBAS-Platform/collectors
cd ./collectors/nvd_nist_cve
````

Install the environment:
**Production**:

```bash
# production environment
poetry install --extras prod
```

**Development** (note that you should also clone the [pyobas](https://github.com/OpenBAS-Platform/client-python) repository [according to these instructions](../README.md#simultaneous-development-on-pyobas-and-a-collector)):

```bash
# development environment
poetry install --extras dev
```

## Usage

```bash
poetry run python -m nvd_nist_cve.openbas_nvd_nist_cve
```

## Configuration

Below are the parameters you'll need to set for OpenBAS:

| Config Parameter | `config.yml`                | Docker Env Var              | Default                                   | Description                                                                                       |
| ---------------- | --------------------------- | --------------------------- | ----------------------------------------- | ------------------------------------------------------------------------------------------------- |
| OpenBAS URL      | `openbas.url`               | `OPENBAS_URL`               | *required*                                | URL to the OpenBAS instance                                                                       |
| OpenBAS token    | `openbas.token`             | `OPENBAS_TOKEN`             | *required*                                | Authentication token to connect to OpenBAS                                                        |
| Collector ID     | `collector.id`              | `COLLECTOR_ID`              | *required*                                | Unique UUIDv4 identifier for this collector instance                                              |
| Collector name   | `collector.name`            | `COLLECTOR_NAME`            | `Cve by NVD NIST`                         | Name of the collector                                                                             |
| Collector type   | `collector.type`            | `COLLECTOR_TYPE`            | `nvd_nist_cve`                            | Type of the collector                                                                             |
| Run interval     | `collector.period`          | `COLLECTOR_PERIOD`          | `7200` (seconds)                          | Time interval at which the collector will run                                                     |
| Log level        | `collector.log_level`       | `COLLECTOR_LOG_LEVEL`       | `warn`                                    | Log verbosity: `debug`, `info`, `warn`, or `error`                                                |
| NVD API base URL | `nvd_nist_cve.api_base_url` | `NVD_NIST_CVE_API_BASE_URL` | `https://services.nvd.nist.gov/rest/json` | Base URL for the NVD CVE API                                                                      |
| NVD API key      | `nvd_nist_cve.api_key`      | `NVD_NIST_CVE_API_KEY`      | *required*                                | Your personal NVD API Key ([Request it here](https://nvd.nist.gov/developers/request-an-api-key)) |

ℹ️ **Important:** Without a valid API key, requests to the NVD API will fail or be rate-limited. Ensure your key is correctly set in either the `config.yml` file or the environment variable `NVD_NIST_CVE_API_KEY`.

## Deployment

### Docker Deployment

Build a Docker Image using the provided `Dockerfile`.

Example:

```bash
# Replace the IMAGE NAME with the appropriate value
docker build . -t [IMAGE NAME]
```

Make sure to replace the environment variables in `docker-compose.yml` with the appropriate configurations for your environment.
Then, start the Docker container with the provided docker-compose.yml:

```bash
docker compose up -d
```

### Manual Deployment

Create a file `config.yml` based on the provided `config.yml.sample`.

Replace the configuration variables with the appropriate values for your environment, including your API key.

Install the environment:

**Production**:

```bash
# production environment
poetry install --extras prod
```

**Development**:

```bash
# development environment
poetry install --extras dev
```

Then, start the collector:

```bash
poetry run python -m nvd_nist_cve.openbas_nvd_nist_cve
```
