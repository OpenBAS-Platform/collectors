# OpenBAS CrowdStrike Collector

The CrowdStrike connector ...

**Note**: Requires subscription to the CrowdStrike Falcon platform. The subscription
details dictate what data is actually available to the connector.

## Installation



## Configuration

The connector can be configured with the following variables:

| Config Parameter             | Docker env var                           | Default                                             | Description                                                                                               |
| ---------------------------- | ---------------------------------------- | --------------------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| `base_url`                   | `CROWDSTRIKE_BASE_URL`                   | `https://api.crowdstrike.com`                       | The base URL for the CrowdStrike APIs.                                                                    |
| `client_id`                  | `CROWDSTRIKE_CLIENT_ID`                  | `ChangeMe`                                          | The CrowdStrike API client ID.                                                                            |
| `client_secret`              | `CROWDSTRIKE_CLIENT_SECRET`              | `ChangeMe`                                          | The CrowdStrike API client secret.                                                                        |
