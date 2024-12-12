# OpenBAS CrowdStrike Collector

The CrowdStrike connector.

**Note**: Requires subscription to the CrowdStrike Falcon platform. The subscription
details dictate what data is actually available to the connector.

## Installation

Get a local copy
```commandline
git checkout https://github.com/OpenBAS-Platform/collectors
```

Install the crowdstrike collector dependencies
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

The connector can be configured with the following variables:

| Config Parameter              | Docker env var              | Default                       | Description                                  |
|-------------------------------|-----------------------------|-------------------------------|----------------------------------------------|
| `openbas`.`url`               | `OPENBAS_URL`               |                               | The URL to the OpenBAS instance              |
| `openbas`.`token`             | `OPENBAS_TOKEN`             |                               | The auth token to the OpenBAS instance       |
| `collector`.`id`              | `COLLECTOR_ID`              |                               | Unique ID of the running collector instance  |
| `collector`.`name`            | `COLLECTOR_NAME`            |                               | Name of the collector (visible in UI)        |
| `collector`.`type`            | `COLLECTOR_TYPE`            |                               | Type of the collector                        |
| `collector`.`period`          | `COLLECTOR_PERIOD`          | 60                            | Period for collection cycle (int, seconds)   |
| `collector`.`log_level`       | `COLLECTOR_LOG_LEVEL`       |                               | Threshold for log severity in console output |
| `collector`.`platform`        | `COLLECTOR_PLATFORM`        |                               | Platform of the collector                    |
| `crowdstrike`.`base_url`      | `CROWDSTRIKE_BASE_URL`      | `https://api.crowdstrike.com` | The base URL for the CrowdStrike APIs.       |
| `crowdstrike`.`client_id`     | `CROWDSTRIKE_CLIENT_ID`     | `CHANGEME`                    | The CrowdStrike API client ID.               |
| `crowdstrike`.`client_secret` | `CROWDSTRIKE_CLIENT_SECRET` | `CHANGEME`                    | The CrowdStrike API client secret.           |

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