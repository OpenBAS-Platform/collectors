# OpenBAS Splunk ES Collector

The Splunk Enterprise Security collector for OpenBAS.

**Note**: Requires access to a Splunk Enterprise Security instance with appropriate search permissions.

## Overview

This collector validates OpenBAS exercise expectations by querying your Splunk ES environment for matching security alerts. When OpenBAS runs security exercises, this collector automatically checks if the expected security alerts were actually generated in your SIEM, providing visibility into your detection capabilities.

## Installation

Get a local copy
```commandline
git checkout https://github.com/OpenBAS-Platform/collectors
cd ./collectors/splunk-es
```

Install the environment:
```shell
poetry install --extras prod
```

## Usage
```commandline
poetry run python -m splunk_es.openaev_splunk_es
```

## Configuration

The collector can be configured with the following variables:

| Config Parameter              | Docker env var              | Default               | Description                                                                                 |
|-------------------------------|-----------------------------|-----------------------|---------------------------------------------------------------------------------------------|
| `openbas`.`url`               | `OPENBAS_URL`               |                       | The URL to the OpenBAS instance                                                             |
| `openbas`.`token`             | `OPENBAS_TOKEN`             |                       | The auth token to the OpenBAS instance                                                      |
| `collector`.`id`              | `COLLECTOR_ID`              |                       | Unique ID of the running collector instance                                                 |
| `collector`.`name`            | `COLLECTOR_NAME`            | `Splunk ES Collector` | Name of the collector (visible in UI)                                                       |
| `collector`.`type`            | `COLLECTOR_TYPE`            | `openaev_splunk_es`   | Type of the collector                                                                       |
| `collector`.`period`          | `COLLECTOR_PERIOD`          | 60                    | Period for collection cycle (int, seconds)                                                  |
| `collector`.`log_level`       | `COLLECTOR_LOG_LEVEL`       | `error`               | Threshold for log severity in console output                                                |
| `splunk`.`base_url`           | `SPLUNK_BASE_URL`           |                       | The base URL for the Splunk ES instance (e.g., `http://splunk:8089`)                        |
| `splunk`.`username`           | `SPLUNK_USERNAME`           |                       | The Splunk username with search permissions                                                 |
| `splunk`.`password`           | `SPLUNK_PASSWORD`           |                       | The Splunk user password                                                                    |

### Required Permissions

The Splunk user must have:
- `search` capability for running SPL queries
- Access to the `notable` index to be able to retrieved Findings and Investigations.

### Sample Configuration

Create a `config.yml` file:

```yaml
openbas:
  url: "http://your-openbas-server:3001"
  token: "your-openbas-api-token"

collector:
  id: "your-unique-collector-id"
  name: "Splunk ES Collector"
  period: 60
  log_level: "info"

splunk:
  base_url: "http://your-splunk-server:8089"
  username: "your-splunk-username"
  password: "your-splunk-password"
```

## Behavior

The collector validates OpenBAS expectations by querying Splunk Enterprise Security for matching security alerts based on IP signatures:

1. **Fetches Expectations**: Retrieves unprocessed expectations from OpenBAS containing IP-based signatures
2. **Queries Splunk ES**: Searches for security alerts matching the expected source and target IP addresses
3. **Validates Results**: Compares found alerts against expectations within the specified time window
4. **Reports Back**: Updates OpenBAS with validation results to show detection success/failure

This process runs continuously based on the configured collection period, providing real-time validation of your security detection capabilities during exercises.

## Troubleshooting

### Common Issues

**Connection Errors**
- Verify `splunk.base_url` includes the management port (usually 8089)
- Check network connectivity between collector and Splunk ES
- Ensure Splunk ES is running and accessible

**Authentication Failures**
- Confirm `splunk.username` and `splunk.password` are correct
- Verify the user account is active and not locked
- Check that the user has the required search capabilities

**No Expectations Found**
- Ensure `collector.id` is registered in OpenBAS
- Verify there are active exercises with IP-based expectations
- Check that the collector is properly configured in OpenBAS

**Permission Denied**
- Verify the Splunk user has `search` capability
- Check index access permissions

### Logging

Set `log_level: debug` in your configuration for detailed troubleshooting information. The collector will log:
- Connection status to OpenBAS and Splunk ES
- Number of expectations processed
- Query execution details
- Any errors encountered during processing

For production environments, use `log_level: info` or `log_level: error` to reduce log volume.