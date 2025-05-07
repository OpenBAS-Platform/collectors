# OpenBAS CrowdStrike Endpoint Security Collector

The CrowdStrike Endpoint Security collector.

**Note**: Requires subscription to the CrowdStrike Falcon platform. The subscription
details dictate what data is actually available to the collector.

## Installation

Get a local copy
```commandline
git checkout https://github.com/OpenBAS-Platform/collectors
```

Install the CrowdStrike Endpoint Security collector dependencies
```commandline
cd collectors/crowdstrike
pip install -r requirements.txt
```

## Usage
```commandline
cd collectors/crowdstrike
python -m crowdstrike.openbas_crowdstrike
```

## Configuration

The collector can be configured with the following variables:

| Config Parameter              | Docker env var              | Default                               | Description                                                                                   |
|-------------------------------|-----------------------------|---------------------------------------|-----------------------------------------------------------------------------------------------|
| `openbas`.`url`               | `OPENBAS_URL`               |                                       | The URL to the OpenBAS instance                                                               |
| `openbas`.`token`             | `OPENBAS_TOKEN`             |                                       | The auth token to the OpenBAS instance                                                        |
| `collector`.`id`              | `COLLECTOR_ID`              |                                       | Unique ID of the running collector instance                                                   |
| `collector`.`name`            | `COLLECTOR_NAME`            | `CrowdStrike Endpoint Security`       | Name of the collector (visible in UI)                                                         |
| `collector`.`type`            | `COLLECTOR_TYPE`            | `crowdStrike_endpoint_security`       | Type of the collector                                                                         |
| `collector`.`period`          | `COLLECTOR_PERIOD`          | 60                                    | Period for collection cycle (int, seconds)                                                    |
| `collector`.`log_level`       | `COLLECTOR_LOG_LEVEL`       |                                       | Threshold for log severity in console output                                                  |
| `collector`.`platform`        | `COLLECTOR_PLATFORM`        | `EDR`                                 | Type of security platform this collector works for. One of: `EDR, XDR, SIEM, SOAR, NDR, ISPM` |
| `crowdstrike`.`api_base_url`  | `CROWDSTRIKE_API_BASE_URL`  | `https://api.crowdstrike.com`         | The base URL for the CrowdStrike APIs.                                                        |
| `crowdstrike`.`ui_base_url`   | `CROWDSTRIKE_UI_BASE_URL`   | `https://falcon.us-2.crowdstrike.com` | The base URL for the CrowdStrike UI you use to see your alerts.                               |
| `crowdstrike`.`client_id`     | `CROWDSTRIKE_CLIENT_ID`     | `CHANGEME`                            | The CrowdStrike API client ID.                                                                |
| `crowdstrike`.`client_secret` | `CROWDSTRIKE_CLIENT_SECRET` | `CHANGEME`                            | The CrowdStrike API client secret.                                                            |

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
python -m unittest
```

### JetBrains PyCharm configuration
To run the collector from within PyCharm, you must:

1. Ensure the requirements are installed correctly:
```commandline
pip install -r requirements.txt
```

2. Create a run configuration in PyCharm with the following settings:
* **Run**: module `crowdstrike.openbas_crowdstrike`
* **Working directory**: `...[path]\collectors\crowdstrike`
* **Deactivate options**: `Add source roots to PYTHONPATH` and `Add content roots to PYTHONPATH`

You may now run or debug the module, run tests...
