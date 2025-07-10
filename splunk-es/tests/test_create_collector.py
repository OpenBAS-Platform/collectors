import pytest
from os import environ as os_environ
from tests.conftest import mock_env_vars
from typing import Any

from splunk_es.splunk_es_collector import SplunkESCollector
from splunk_es.exceptions import SplunkESConfigurationError

# --------
# Fixtures
# --------

@pytest.fixture()
def collector_config() -> dict[str, str]:  # type: ignore
    """Fixture for minimum required configuration."""
    return {
        "OPENBAS_URL": "http://fake-url",
        "OPENBAS_TOKEN": "fake-obas-token",
        "COLLECTOR_ID": "fake-collector-id",
        "SPLUNK_BASE_URL": "http://fake-splunk",
        "SPLUNK_USERNAME": "splunk-username",
        "SPLUNK_PASSWORD": "splunk-password",
        "COLLECTOR_ICON_FILEPATH": "./splunk_es/img/splunk-logo.png",
        "COLLECTOR_LOG_LEVEL": "debug"
    }

# --------
# Tests
# --------

# Scenario: Create a collector with success.
def test_success_create_collector(capfd, collector_config):  # type: ignore
    """Test that the main function initializes and start the SplunkESCollector."""
    # Given I have a valid configuration to start the SplunkESCollector.
    data = {**collector_config}
    mock_env = _given_setup_config(data)

    # When I create the collector.
    collector= _when_create_collector()

    # Then the collector should be created successfully
    _then_collector_created_successfully(capfd, mock_env, collector, data)

# Scenario: Create a collector in failure
def test_connector_config_invalid_connector_type() -> None:
    """Test for the connector for  invalid connector type values."""
    # Given an empty configuration are provided.
    data = {}
    mock_env = _given_setup_config(data)

    # Then the connector config should raise a custom ConfigurationException
    with pytest.raises(SplunkESConfigurationError):
        # When the collector is created
        collector  = _when_create_collector()

# ---------
# Given
# ---------

# Given setup config
def _given_setup_config(data: dict[str, str]) -> Any:  # type: ignore
    """Set up the environment variables for the test."""
    mock_env = mock_env_vars(os_environ, data)
    return mock_env

# ---------
# When
# ---------

# When the collector is created
def _when_create_collector() -> SplunkESCollector:  # type: ignore
    """Create the connector."""
    collector = SplunkESCollector()
    return collector

# ---------
# Then
# ---------

# Then the collector should be created successfully
def _then_collector_created_successfully(capfd, mock_env, collector, data) -> None:  # type: ignore
    """Check if the connector was created successfully."""
    assert collector is not None  # noqa: S101

    for key, value in data.items():
        if "log_level" in key.lower():
            assert collector._configuration.get("log_level") == value  # noqa: S101
        else:
            assert collector._configuration.get(key.lower()) == value  # noqa: S101


    log_records = capfd.readouterr()
    if collector._configuration.get("log_level") in ["info", "debug"]:
        registered_message = f'"name": "{collector._configuration.get("collector_name")}", "message": "Splunk ES Collector initialized successfully"}}'
        assert registered_message in log_records.err  # noqa: S101

    mock_env.stop()
