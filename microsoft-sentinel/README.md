# OpenBAS Microsoft Sentinel Collector

The Microsoft sentinel collector allows you to validate prevention or expectation type expectations.

By searching in your tool's logs and based on connected EDRs, the collector tries to match the attack launched with the logs reported in your SIEM.

## Configuration variables

Below are the properties you'll need to set for OpenBAS:

| Property                           | Docker environment variable          | Mandatory | Description                                        |
|------------------------------------|--------------------------------------|-----------|----------------------------------------------------|
| Admin OBAS token                   | `OPENBAS_TOKEN`                      | Yes       | The token of your openbas admin user.              |
| Collector UUID                     | `COLLECTOR_ID`                       | Yes       | A random UUID to idenfity your collector.          |
| Collector name                     | `COLLECTOR_NAME`                     | Yes       | The name of your collector.                        |
| Collector type                     | `COLLECTOR_TYPE`                     | No        | The type of your collector.                        |
| Microsoft sentinel tenant ID       | `MICROSOFT_SENTINEL_TENANT_ID`       | Yes       | Your tenant ID.                                    |
| Microsoft sentinel client ID       | `MICROSOFT_SENTINEL_CLIENT_ID`       | Yes       | Your client ID.                                    |
| Microsoft sentinel client Secret   | `MICROSOFT_SENTINEL_CLIENT_SECRET`   | Yes       | Your client secret.                                |
| Microsoft sentinel subscription ID | `MICROSOFT_SENTINEL_SUBSCRIPTION_ID` | Yes       | Your subscription id.                              |
| Microsoft sentinel worspace ID     | `MICROSOFT_SENTINEL_WORKSPACE_ID`    | Yes       | Your workspace id.                                 |
| Microsoft sentinel resource group  | `MICROSOFT_SENTINEL_RESOURCE_GROUP`  | Yes       | Your resource group.                               |
| UUID linked collectors             | `MICROSOFT_SENTINEL_EDR_COLLECTORS`  | Yes       | List of collector EDR link to your collector SIEM. |
