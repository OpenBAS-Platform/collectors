# OpenBAS collectors

[![Website](https://img.shields.io/badge/website-openbas.io-blue.svg)](https://filigran.io/)
[![Slack Status](https://img.shields.io/badge/slack-3K%2B%20members-4A154B)](https://community.filigran.io)

The following repository is used to store the OpenBAS collectors for the platform integration with other tools and applications.

## OpenBAS usage

Collectors must be started along with the platform api, using "lib" directory
- openbas-api.jar
- lib/openbas-collector-01.jar

> java -Dloader.path=file:lib/ -jar openbas-api.jar

## Collectors list and statuses

This repository is used to host injectors that are supported by the core development team of OpenBAS. Nevertheless, the community is also developping a lot of injectors, third-parties modules directly linked to OpenBAS. You can find the list of all available injectors and plugins in the [OpenBAS ecosystem dedicated space](https://filigran.notion.site/OpenBAS-Ecosystem-30d8eb73d7d04611843e758ddef8941b).

## Contributing

If you want to help use improve or develop new injector, please check out the **[development documentation for new injectors](https://docs.openbas.io/latest/development/injectors)**. If you want to make your connector available to the community, **please create a Pull Request on this repository**, then we will integrate it to the CI and in the [OpenBAS ecosystem]().

## License

**Unless specified otherwise**, connectors are released under the [Apache 2.0](https://github.com/OpenBAS-Platform/injectors/blob/master/LICENSE). If an injector is released by its author under a different license, the subfolder corresponding to it will contain a *LICENSE* file.

## About

OpenBAS is a product designed and developed by the company [Filigran](https://filigran.io).

<a href="https://filigran.io" alt="Filigran"><img src="https://filigran.io/wp-content/uploads/2023/08/filigran_text_medium.png" width="200" /></a>
