# Contributing to OpenBAS Collectors

First off, thank you for considering contributing to the OpenBAS project! It's people like you that make OpenBAS such a great tool. This document provides guidelines for contributing to a new or existing OpenBAS collector.

## Code of Conduct

This project and everyone participating in it is governed by the [OpenBAS Code of Conduct](https://github.com/OpenBAS-Platform/openbas/blob/master/CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## How Can I Contribute?

You can contribute in several ways: by reporting bugs, suggesting enhancements, improving documentation, or by contributing code.

### Creating a New Collector

The most common way to contribute is to create a new collector for a tool that is not yet supported. This guide provides a step-by-step process for creating a new collector by using an existing one as a template.

## Development Workflow

### Prerequisites

- Python 3.11+
- Poetry for dependency management
- Access to an OpenBAS instance for testing
- Access to the target tool you want to build a collector for (e.g., Splunk, Sentinel, etc.)

### Project Structure

All collectors follow a standardized structure to ensure consistency and maintainability. We will use a generic `my_collector` name as an example. When creating a new collector, you should replace `my_collector` with the name of your integration (e.g., `splunk_es`, `sentinel`, etc.).

```
/collectors/my-collector/
├── my_collector/
│   ├── __init__.py             # Package initializer
│   ├── __main__.py             # Main entry point for `python -m`
│   ├── my_collector_collector.py    # The main collector daemon class
│   ├── my_collector_client.py       # Client for interacting with the external tool's API
│   ├── configuration.py        # Configuration management
│   ├── expectation_manager.py  # Handles batch processing of expectations
│   └── exceptions.py           # Custom exceptions
├── tests/
│   └── ...
├── .dockerignore
├── .gitignore
├── docker-compose.yml
├── Dockerfile
├── poetry.lock
├── pyproject.toml
└── README.md
```

### Step-by-Step Guide to Creating a New Collector

#### 1. Copy an Existing Collector

The easiest way to start is by copying an existing collector. The `splunk-es` collector is a good template as it demonstrates best practices like batch processing and clear separation of concerns.

```bash
cp -r collectors/splunk-es collectors/my-collector
cd collectors/my-collector
```

#### 2. Rename Files and Directories

Rename the package directory and the internal files from `splunk_es` to `my_collector`.

```bash
mv splunk_es my_collector
mv my_collector/splunk_es_collector.py my_collector/my_collector_collector.py
mv my_collector/splunk_es_client.py my_collector/my_collector_client.py
mv my_collector/splunk_es_configuration.py my_collector/configuration.py
# The expectation_manager.py and exceptions.py can often be reused with minimal changes.
```

#### 3. Update `pyproject.toml`

Modify the `pyproject.toml` file to reflect your new collector's metadata and dependencies.

- **`[project.name]`**: Change `openbas-splunk-es-collector` to `openbas-my-collector-collector`.
- **`[tool.poetry.packages]`**: Update the include path to `{include = "my_collector"}`.
- **Dependencies**: Add any new Python libraries your collector needs to communicate with the target tool's API.

#### 4. Implement the Configuration (`my_collector/configuration.py`)

- Rename the class `SplunkESConfiguration` to `MyCollectorConfiguration`.
- In `_get_my_collector_config_hints()`, define the configuration parameters your collector needs. This includes credentials, API endpoints, and any other settings required to connect to your target tool.
- Update the `validate()` method to check for all required fields.
- Create a `get_my_collector_config()` helper method to return a dictionary of just the tool-specific settings.

**Example:**
```python
# my_collector/configuration.py

class MyCollectorConfiguration(Configuration):
    # ...
    @staticmethod
    def _get_my_collector_config_hints() -> dict:
        return {
            # ... (keep openbas and collector hints)
            # Add your tool-specific hints
            "my_collector_api_url": {
                "env": "MY_COLLECTOR_API_URL",
                "file_path": ["my_collector", "api_url"],
            },
            "my_collector_api_key": {
                "env": "MY_COLLECTOR_API_KEY",
                "file_path": ["my_collector", "api_key"],
            },
        }

    def validate(self) -> bool:
        # ...
        required_fields = [
            "openbas_url",
            "openbas_token",
            "collector_id",
            "my_collector_api_url",
            "my_collector_api_key",
        ]
        # ...

    def get_my_collector_config(self) -> dict:
        return {
            "api_url": self.get("my_collector_api_url"),
            "api_key": self.get("my_collector_api_key"),
        }
```

#### 5. Implement the API Client (`my_collector/my_collector_client.py`)

This is where the core logic for interacting with the external tool resides.

- Rename `SplunkESClient` to `MyCollectorClient`.
- **`__init__`**: Update it to accept and validate the configuration from `MyCollectorConfiguration`.
- **`build_ip_search_query`**: Modify this method to generate the correct query syntax for your target tool. The goal is to search for security alerts based on source and/or target IP addresses.
- **`execute_query`**: **This is the most critical part.** Replace the mock data implementation with actual code that sends a request to your tool's API using the query from the previous step. Handle authentication, connection errors, and API rate limits gracefully.
- **`convert_alert_to_detection_data`**: Adapt this method to transform the raw alert from your tool into the standardized `alert_data` format that the `OpenBASDetectionHelper` expects.

#### 6. Implement the Collector (`my_collector/my_collector_collector.py`)

This class orchestrates the entire workflow.

- Rename `SplunkESCollector` to `MyCollectorCollector`.
- Update all imports to use the new file and class names (`MyCollectorConfiguration`, `MyCollectorClient`).
- In the `__init__` and `_setup` methods, ensure you are instantiating your new `MyCollectorConfiguration` and `MyCollectorClient` classes.
- The rest of the file, including the processing loop (`_process_expectations_callback`), can often remain unchanged as it relies on the agnostic `ExpectationManager`.

#### 7. Update Package Initializers

- **`my_collector/__init__.py`**: Update the `__all__` list and import statements to export your new classes.
- **`my_collector/__main__.py`**: Update the import to point to your new main entry point if you modified it.

#### 8. Update Documentation

- **`README.md`**: Update the README with the correct name, description, configuration parameters, and usage instructions for your new collector.
- **`config.yml.sample`**: Provide a sample configuration file for users.

### Code Style

We use `black` for code formatting and `isort` for import sorting to maintain a consistent style. Please run these tools on your code before submitting a contribution.

```bash
poetry run black .
poetry run isort .
```

### Submitting Your Contribution

1.  **Fork** the [OpenBAS/collectors](https://github.com/OpenBAS-Platform/collectors) repository.
2.  **Create a new branch** for your feature (`git checkout -b feature/my-new-collector`).
3.  **Commit** your changes (`git commit -m 'feat: Add collector for MyCollector'`).
4.  **Push** your branch to your fork (`git push origin feature/my-new-collector`).
5.  **Open a Pull Request** to the `master` branch of the main repository.

Thank you for your contribution!
