# OpenAEV NVD NIST CVE collector

The NVD NIST CVE collector is a standalone Python process that collect data from the NVD (National Vulnerability Database).

### CVE and CVSS base score V3.1

CVEs are assigned a criticality score (CVSS) making it possible to prioritize vulnerabilities and thus prioritize IS
security projects.   
As of July 13th, 2022, the NVD will no longer generate new information for CVSS v2.
Existing CVSS V2 information will remain in the database, but the NVD will no longer actively populate CVSS V2 for new
CVEs.    
CVSS V3.1 was released in June 2019, thus most CVE published before 2019 do not include the `cvssMetricV31` object. The
exception are CVE published before 2019 that were later reanalyzed or modified.
These CVE may have been updated to include CVSS V3.1 information. If the CVE was updated in this way, the API response
would include this optional information.   

This collector **will import all CVE with CVSS V3.1 base score**.

## Requirements
- OpenAEV Platform version 1.19 or higher
- An API Key for accessing ([Request an API Key for NVD](https://nvd.nist.gov/developers/request-an-api-key)


## Installation

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
poetry run python -m nvd_nist_cve.openaev_nvd_nist_cve
```

## Configuration

The collector can be configured with the following variables:

| Config Parameter             | Docker env var              | Default                                   | Description                                                                                                   |
|------------------------------|-----------------------------|-------------------------------------------|---------------------------------------------------------------------------------------------------------------|
| `openaev`.`url`              | `OPENAEV_URL`               |                                           | The URL to the OpenAEV instance                                                                               |
| `openaev`.`token`            | `OPENAEV_TOKEN`             |                                           | The auth token to the OpenAEV instance                                                                        |
| `collector`.`id`             | `COLLECTOR_ID`              |                                           | Unique ID of the running collector instance                                                                   |
| `collector`.`name`           | `COLLECTOR_NAME`            | `Cve by NVD NIST`                         | Name of the collector (visible in UI)                                                                         |
| `collector`.`type`           | `COLLECTOR_TYPE`            | `nvd_nist_cve`                            | Type of the collector                                                                                         |
| `collector`.`period`         | `COLLECTOR_PERIOD`          | 7200                                      | Interval in seconds to check and import new CVEs. Nist advice a minimum of 2hours                             |
| `collector`.`log_level`      | `COLLECTOR_LOG_LEVEL`       |                                           | Threshold for log severity in console output                                                                  |
| `crowdstrike`.`api_base_url` | `NVD_NIST_CVE_API_BASE_URL` | `https://services.nvd.nist.gov/rest/json` | The base URL for the CVE NVD APIs.                                                                            |
| `crowdstrike`.`ui_base_url`  | `NVD_NIST_CVE_API_KEY`      |                                           | API Key for the CVE NVD API.([Request an API Key for NVD](https://nvd.nist.gov/developers/request-an-api-key) |
