# OpenEx Caldera collector

The Caldera collector is a maven dependency that collect agents from a Caldera instance and import them as assets in
OpenEx.

## Summary

- [Requirements](#requirements)
  - [Deploy a Caldera instance](#deploy-a-caldera-instance)
- [Configuration variables](#configuration-variables)
- [Behavior](#behavior)
    - [Mapping](#mapping)
- [Sources](#sources)

---

### Requirements

- OpenEx Platform version 3.6.0 or higher with caldera collector dependency
- A deployed Caldera instance

#### Deploy a Caldera instance

To deploy a Caldera instance, you can follow the [documentation](https://caldera.readthedocs.io/en/latest/) and use
this [github repository](https://github.com/mitre/caldera?tab=readme-ov-file).

### Configuration variables

Below are the properties you'll need to set for OpenEx:

| Property                 | application.properties     | Docker environment variable   | Mandatory | Description                                                                         |
|--------------------------|----------------------------|-------------------------------|-----------|-------------------------------------------------------------------------------------|
| Enable Caldera collector | collector.caldera.enable   | `COLLECTOR.CALDERA.ENABLE`    | Yes       | Enable the Caldera collector.                                                       |
| Caldera URL              | collector.caldera.url      | `COLLECTOR.CALDERA.URL`       | Yes       | The URL of the Caldera instance.                                                    |
| Caldera API Key          | collector.caldera.api-key  | `COLLECTOR.CALDERA.API-KEY`   | Yes       | The API Key for the rest API of the Caldera instance.                               |
| Caldera polling interval | collector.caldera.interval | `COLLECTOR.CALDERA.INTERVAL`  | No        | The time interval in seconds where the collect is triggered. Default is 60 seconds. |

### Behavior

Each interval, a job retrieves the deployed agents on Caldera and populates the OpenEx database by creating Assets.
Deduplication is done thanks to the caldera `paw` property :
  - if there is no asset on OpenEx with this `paw`, a new asset is created
  - if there is an asset on OpenEx with this `paw`, this asset is updated

There is no automatic deletion of OpenEx assets if Caldera agents no longer exist

#### Mapping

| Agent Property  | Asset Property |
|-----------------|----------------|
| paw             | externalId     |
| paw             | name           |
| host_ip_addrs   | ips            |
| platform        | platform       |
| last_seen       | lastSeen       |

### Sources

- [Caldera](https://caldera.mitre.org/)
