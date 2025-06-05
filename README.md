# OpenBAS collectors

[![Website](https://img.shields.io/badge/website-openbas.io-blue.svg)](https://openbas.io)
[![CircleCI](https://circleci.com/gh/OpenBAS-Platform/collectors.svg?style=shield)](https://circleci.com/gh/OpenBAS-Platform/collectors/tree/main)
[![Slack Status](https://img.shields.io/badge/slack-3K%2B%20members-4A154B)](https://community.filigran.io)

The following repository is used to store the OpenBAS collectors for the platform integration with other tools and
applications. To know how to enable collectors on OpenBAS, please read the [dedicated documentation](https://docs.openbas.io/latest/deployment/ecosystem/collectors).

## Collectors list and statuses

This repository is used to host collectors that are supported by the core development team of OpenBAS.
Nevertheless, the community is also developing a lot of collectors, third-parties modules directly linked to OpenBAS.
You can find the list of all available collectors and plugins in the [OpenBAS ecosystem dedicated space](https://filigran.notion.site/OpenBAS-Ecosystem-30d8eb73d7d04611843e758ddef8941b).

## Contributing

If you want to help use improve or develop new collector, please check out the
**[development documentation for new collectors](https://docs.openbas.io/latest/development/collectors)**. If you want to make your collectors available to the community,
**please create a Pull Request on this repository**, then we will integrate it to the CI and in
the [OpenBAS ecosystem](https://filigran.notion.site/OpenBAS-Ecosystem-30d8eb73d7d04611843e758ddef8941b).

## Development
In this repository, you need to have `python >= 3.11` and `poetry >= 2.1`. Install the development environment with:
> [!IMPORTANT]
> This repository uses "mutually exclusive extra markers" to manage the source of the pyobas dependency. Make sure to
> follow the steps to set up poetry correctly to handle this case:
> https://python-poetry.org/docs/dependency-specification/#exclusive-extras
```shell
poetry install --extras dev
```

### Creating a new collector

#### Project setup
Assuming a new collector by the name of `new_collector`, create a skeleton directory with:
```shell
poetry new new_collector
```

#### `pyobas` dependency
We wish to retain the possibility to develop simultaneously on `pyobas` and collectors. We rely on PEP 508 environment
markers to alternatively install a local path `pyobas` dependency or a released version from PyPI; specifically the `extra`
marker.

Navigate to the new directory and edit `pyproject.toml`.
```shell
vim new_collector/pyproject.toml
```
(or open the file in your favourite editor).

Here's the expression for the pyobas dependency, including the `extra` definition:
```toml
[tool.poetry.dependencies]
pyobas = [
    { markers = "extra == 'prod' and extra != 'dev' and extra != 'ci'", version = "<latest pyobas release on PyPI>", source = "pypi"  },
    { markers = "extra == 'dev' and extra != 'prod' and extra != 'ci'", path = "../../client-python", develop = true },
    { markers = "extra == 'ci' and extra != 'prod' and extra != 'dev'", git = 'https://github.com/OpenBAS-Platform/client-python', branch = 'release/current' },
]

[tool.poetry.extras]
prod = []
dev = []
ci = []
```

### Simultaneous development on pyobas and a collector
The collectors repository is set to assume that in the event of a simultaneous development work on both pyobas
and collectors, the `pyobas` repository is cloned in a directory at the same level as the collectors root directory,
and is named strictly `client-python`
Here's an example layout:
```
.
├── client-python       <= mandatory dir name
│   ├── docs
│   ├── pyobas
│   ├── scripts
│   └── test
└── collectors          <= this repo root dir
    ├── atomic-red-team
    ├── crowdstrike
    ├── microsoft-defender
    ├── microsoft-entra
    ├── microsoft-sentinel
    ├── mitre-attack
    ├── scripts
    └── tanium-threat-response
```

## License

**Unless specified otherwise**, collectors are released under the [Apache 2.0](https://github.com/OpenBAS-Platform/collectors/blob/master/LICENSE). If a collector is released by its
author under a different license, the subfolder corresponding to it will contain a *LICENSE* file.

## About

OpenBAS is a product designed and developed by the company [Filigran](https://filigran.io).

<a href="https://filigran.io" alt="Filigran"><img src="https://github.com/OpenBAS-Platform/openbas/raw/master/.github/img/logo_filigran.png" width="300" /></a>