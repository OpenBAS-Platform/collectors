"""
Splunk ES Collector Configuration.

This module provides configuration management for the Splunk ES collector,
leveraging the pyobas Configuration class with Splunk-specific hints.
"""

from pyobas.configuration import Configuration

from splunk_es.exceptions import SplunkESConfigurationError


class SplunkESConfiguration(Configuration):
    """
    Splunk ES specific configuration class.

    Extends the base Configuration class with Splunk ES specific
    configuration hints and validation.
    """

    def __init__(self):
        """
        Initialize Splunk ES configuration.

        Raises:
            SplunkESConfigurationError: If configuration invalid
        """
        config_hints = self._get_splunk_es_config_hints()

        try:
            super().__init__(config_hints=config_hints)
        except Exception as e:
            raise SplunkESConfigurationError(f"Failed to initialize configuration: {e}") from e

    @staticmethod
    def _get_splunk_es_config_hints() -> dict:
        """
        Get configuration hints for Splunk ES collector.

        Returns:
            Dictionary of configuration hints
        """
        return {
            # OpenBAS configuration
            "openbas_url": {
                "env": "OPENBAS_URL",
                "file_path": ["openbas", "url"],
            },
            "openbas_token": {
                "env": "OPENBAS_TOKEN",
                "file_path": ["openbas", "token"],
            },

            # Collector configuration
            "collector_id": {
                "env": "COLLECTOR_ID",
                "file_path": ["collector", "id"],
            },
            "collector_name": {
                "env": "COLLECTOR_NAME",
                "file_path": ["collector", "name"],
                "default": "Splunk ES Collector",
            },
            "collector_type": {
                "env": "COLLECTOR_TYPE",
                "file_path": ["collector", "type"],
                "default": "openaev_splunk_es",
            },
            "collector_period": {
                "env": "COLLECTOR_PERIOD",
                "file_path": ["collector", "period"],
                "is_number": True,
                "default": 60,
            },
            "collector_icon_filepath": {
                "env": "COLLECTOR_ICON_FILEPATH",
                "file_path": ["collector", "icon_filepath"],
                "default":  "./img/splunk-logo.png"
            },
            "log_level": {
                "env": "COLLECTOR_LOG_LEVEL",
                "file_path": ["collector", "log_level"],
                "default": "error",
            },

            # Splunk ES configuration
            "splunk_base_url": {
                "env": "SPLUNK_BASE_URL",
                "file_path": ["splunk", "base_url"],
            },
            "splunk_username": {
                "env": "SPLUNK_USERNAME",
                "file_path": ["splunk", "username"],
            },
            "splunk_password": {
                "env": "SPLUNK_PASSWORD",
                "file_path": ["splunk", "password"],
            },
        }

    def validate(self) -> bool:
        """
        Validate that all required configuration values are present.

        Returns:
            True if configuration is valid

        Raises:
            SplunkESConfigurationError: If required configuration is missing
        """
        required_fields = [
            "openbas_url",
            "openbas_token",
            "collector_id",
            "splunk_base_url",
            "splunk_username",
            "splunk_password",
        ]

        missing_fields = []
        for field in required_fields:
            value = self.get(field)
            if not value or (isinstance(value, str) and value.strip() == ""):
                missing_fields.append(field)

        if missing_fields:
            raise SplunkESConfigurationError(
                f"Missing required configuration fields: {', '.join(missing_fields)}"
            )

        return True

    def get_splunk_config(self) -> dict:
        """
        Get Splunk-specific configuration as a dictionary.

        Returns:
            Dictionary containing Splunk configuration
        """
        return {
            "base_url": self.get("splunk_base_url"),
            "username": self.get("splunk_username"),
            "password": self.get("splunk_password"),
        }
