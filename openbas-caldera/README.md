# OpenBAS Caldera collector

The Caldera collector is a maven dependency that collect agents from a Caldera instance and import them as assets in
OpenBAS.

## Summary

- [Requirements](#requirements)
  - [Deploy a Caldera instance](#deploy-a-caldera-instance)
- [Configuration variables](#configuration-variables)
- [Behavior](#behavior)
    - [Mapping](#mapping)
- [Sources](#sources)

---

### Requirements

- OpenBAS Platform version 3.6.0 or higher with caldera collector dependency
- A deployed Caldera instance

#### Deploy a Caldera instance

To deploy a Caldera instance, you can follow the [documentation](https://caldera.readthedocs.io/en/latest/) and use
this [github repository](https://github.com/mitre/caldera?tab=readme-ov-file).

### Configuration variables

Below are the properties you'll need to set for OpenBAS:

| Property                 | application.properties     | Docker environment variable  | Mandatory | Description                                                                         |
|--------------------------|----------------------------|------------------------------|-----------|-------------------------------------------------------------------------------------|
| Enable Caldera collector | collector.caldera.enable   | `COLLECTOR_CALDERA_ENABLE`   | Yes       | Enable the Caldera collector.                                                       |
| Collector ID             | collector.caldera.id       | `COLLECTOR_CALDERA_ID`       | Yes       | The ID of the collector.                                                            |
| Caldera URL              | collector.caldera.url      | `COLLECTOR_CALDERA_URL`      | Yes       | The URL of the Caldera instance.                                                    |
| Caldera API Key          | collector.caldera.api-key  | `COLLECTOR_CALDERA_API_KEY`  | Yes       | The API Key for the rest API of the Caldera instance.                               |
| Caldera polling interval | collector.caldera.interval | `COLLECTOR_CALDERA_INTERVAL` | No        | The time interval in seconds where the collect is triggered. Default is 60 seconds. |

### Behavior

Each interval, a job retrieves the deployed agents on Caldera and populates the OpenBAS database by creating Assets.
Deduplication is done thanks to the caldera `paw` property :
  - if there is no asset on OpenBAS with this `paw`, a new asset is created
  - if there is an asset on OpenBAS with this `paw` and the source of creation is only Caldera, this asset is updated

There is no automatic deletion of OpenBAS assets if Caldera agents no longer exist.

### Mapping

| Agent Property | Asset Property |
|----------------|----------------|
| paw            | externalId     |
| host - paw     | name           |
| host_ip_addrs  | ips            |
| host           | hostname       |
| platform       | platform       |
| last_seen      | lastSeen       |

### Sources

- [Caldera](https://caldera.mitre.org/)
