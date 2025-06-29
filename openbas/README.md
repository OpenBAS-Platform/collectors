# OpenBAS Datasets Collector

This collector allows to import the OpenBAS payloads repository in order to pre-populate your OpenBAS instance with out-of-the-box payloads.

## Configuration

The collector can be configured with the following variables:

| Config Parameter               | Docker env var           | Default                                                                                | Mandatory | Description                                  |
|--------------------------------|--------------------------|----------------------------------------------------------------------------------------|-----------|----------------------------------------------|
| `openbas`.`url`                | `OPENBAS_URL`            |                                                                                        | Yes       | The URL to the OpenBAS instance              |
| `openbas`.`token`              | `OPENBAS_TOKEN`          |                                                                                        | Yes       | The auth token to the OpenBAS instance       |
| `collector`.`id`               | `COLLECTOR_ID`           |                                                                                        | Yes       | Unique ID of the running collector instance  |
| `collector`.`name`             | `COLLECTOR_NAME`         | `OpenBAS Datasets`                                                                     | No        | Name of the collector (visible in UI)        |
| `collector`.`type`             | `COLLECTOR_TYPE`         | `openbas`                                                                              | No        | Type of the collector                        |
| `collector`.`period`           | `COLLECTOR_PERIOD`       | 604800                                                                                 | No        | Period for collection cycle (int, seconds)   |
| `collector`.`log_level`        | `COLLECTOR_LOG_LEVEL`    |                                                                                        | No        | Threshold for log severity in console output |
| `openbas`.`url_prefix`         | `OPENBAS_URL_PREFIX`     | `https://raw.githubusercontent.com/OpenBAS-Platform/payloads/refs/heads/main/`         | No        | URL prefix to look for the content           |

## Behavior

The collector retrieves payloads from the Filigran OpenBAS payload repository. 