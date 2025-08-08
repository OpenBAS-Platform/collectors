"""
Splunk ES Client.

This module provides a client for interacting with Splunk ES,
including query building, alert fetching, and alert data conversion
for use with OpenBAS expectation matching.
"""

from pyobas.signatures.types import SignatureTypes

from splunk_es.exceptions import (
    SplunkESAuthenticationError,
    SplunkESConnectionError,
    SplunkESQueryError,
)
from splunk_es.splunk_es_models import SplunkSearchResponse, SplunkAlert

import requests



class SplunkESClient:
    """
    Client for interacting with Splunk ES.

    Handles SPL query building, execution, and alert data conversion
    for OpenBAS expectation matching.
    """

    def __init__(self, config: dict, logger):
        """
        Initialize Splunk ES client.

        Args:
            config: Splunk configuration dictionary
            logger: Logger instance

        Raises:
            SplunkESConnectionError: If configuration is invalid
        """
        self.config = config
        self.logger = logger

        required_fields = ["base_url", "username", "password"]
        missing = [field for field in required_fields if not config.get(field)]
        if missing:
            raise SplunkESConnectionError(
                f"Missing required Splunk configuration: {', '.join(missing)}"
            )

        self.base_url = config["base_url"].rstrip("/")
        self.username = config["username"]
        self.password = config["password"]
        self.index = config.get("index")

        self.logger.info(
            f"Initialized Splunk ES client for {self.base_url}"
            f"{f' (index: {self.index})' if self.index else ''}"
        )

    def build_ip_search_query(
        self,
        source_ips: list[str],
        target_ips: list[str],
        time_range: str = "earliest=-1h@h latest=now",
    ) -> str:
        """
        Build SPL query to search for IP-based alerts.

        Args:
            source_ips: List of source IP addresses
            target_ips: List of target IP addresses
            time_range: Time range for the search

        Returns:
            SPL query string

        Raises:
            SplunkESQueryError: If query building fails
        """
        try:
            base_query = "`notable`"

            if self.index:
                base_query += f" index={self.index}"

            ip_conditions = []

            if source_ips:
                src_fields = ["src_ip", "src", "source_ip", "client_ip"]
                src_conditions = []
                for field in src_fields:
                    field_condition = " OR ".join([f'{field}="{ip}"' for ip in source_ips])
                    src_conditions.append(f"({field_condition})")

                if src_conditions:
                    ip_conditions.append(f"({' OR '.join(src_conditions)})")

            if target_ips:
                dst_fields = ["dst_ip", "dest", "dest_ip", "destination_ip", "server_ip"]
                dst_conditions = []
                for field in dst_fields:
                    field_condition = " OR ".join([f'{field}="{ip}"' for ip in target_ips])
                    dst_conditions.append(f"({field_condition})")

                if dst_conditions:
                    ip_conditions.append(f"({' OR '.join(dst_conditions)})")

            if ip_conditions:
                combined_conditions = f"({' OR '.join(ip_conditions)})"
                full_query = f"{base_query} {combined_conditions}"
            else:
                full_query = base_query

            full_query += f" {time_range}"
            full_query += " | table _time, src_ip, src, source_ip, client_ip, dst_ip, dest, dest_ip, destination_ip, server_ip, signature, rule_name, event_type, severity, _raw"
            full_query += " | sort -_time"

            self.logger.debug(f"Built SPL query: {full_query}")
            return full_query

        except Exception as e:
            raise SplunkESQueryError(f"Failed to build SPL query: {e}") from e

    def execute_query(self, spl_query: str) -> SplunkSearchResponse:
        """
        Execute SPL query against Splunk ES.

        Args:
            spl_query: SPL query string

        Returns:
            List of alert dictionaries

        Raises:
            SplunkESConnectionError: If connection fails
            SplunkESAuthenticationError: If authentication fails
            SplunkESQueryError: If query execution fails
        """
        try:
            self.logger.info("Executing Splunk ES query...")
            self.logger.debug(f"Query: {spl_query}")

            # In production, this would connect to actual Splunk ES
            # alerts = self._execute_rest_query(spl_query)

            # For now, return mock data as in the PoC
            mock_alerts = self._get_mock_alerts()

            self.logger.info(f"Query completed: Retrieved {len(mock_alerts.results)} alerts")
            if mock_alerts.results:
                self.logger.debug(f"Sample alert: {mock_alerts.results[0]}")

            return mock_alerts

        except Exception as e:
            if "authentication" in str(e).lower():
                raise SplunkESAuthenticationError(f"Splunk authentication failed: {e}") from e
            elif "connection" in str(e).lower():
                raise SplunkESConnectionError(f"Splunk connection failed: {e}") from e
            else:
                raise SplunkESQueryError(f"Query execution failed: {e}") from e

    def _execute_rest_query(self, spl_query: str) -> SplunkSearchResponse:
        """
        Execute a query against the Splunk REST API.

        This function orchestrates the authentication using username/password,
        and the api call to the endpoint `https://<host>:<mPort>/services/search/jobs`
        with the query params `exec_mode=oneshot` and `output_mode=json` and `count=0`
        so that we retrieved all the matching alerts in the timeframe desired.

        Args:
            spl_query: The SPL query to execute.

        Returns:
            A list of alert dictionaries.
        """
        api_endpoint = f"{self.base_url}/services/search/jobs"

        params = {
            "search": f"search {spl_query}",
            "exec_mode": "oneshot",
            "output_mode": "json",
            "count": 0,
        }

        try:
            response = requests.post(
                api_endpoint,
                data=params,
                auth=(self.username, self.password),
            )
            response.raise_for_status()

            return SplunkSearchResponse(**response.json())

        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                raise SplunkESAuthenticationError("Authentication with Splunk ES failed.") from e
            else:
                raise SplunkESQueryError(f"Splunk ES query failed with status code {e.response.status_code}: {e.response.text}") from e
        except requests.exceptions.RequestException as e:
            raise SplunkESConnectionError(f"Could not connect to Splunk ES: {e}") from e

    def _get_mock_alerts(self) -> SplunkSearchResponse:
        """
        Get mock alert data for testing.

        Returns:
            List of mock alert dictionaries
        """
        return SplunkSearchResponse(
            results=[
                {
                    "_time": "2024-01-15T10:30:00.000Z",
                    "src_ip": "10.0.0.2",
                    "dst_ip": "68.183.68.83",
                    "signature": "Suspicious Network Activity",
                    "rule_name": "High Volume Data Transfer",
                    "event_type": "network",
                    "severity": "medium",
                    "_raw": "Mock security alert data for IP-based detection",
                },
                {
                    "_time": "2024-01-15T10:35:00.000Z",
                    "src_ip": "192.168.1.100",
                    "dst_ip": "203.0.113.5",
                    "signature": "Malicious IP Communication",
                    "rule_name": "Known Bad IP",
                    "event_type": "threat_intel",
                    "severity": "high",
                    "_raw": "Another mock alert for testing batch processing",
                },
                {
                    "_time": "2024-01-15T10:40:00.000Z",
                    "source_ip": "172.16.0.50",
                    "destination_ip": "185.220.101.32",
                    "signature": "Tor Exit Node Communication",
                    "rule_name": "Tor Network Usage",
                    "event_type": "anonymization",
                    "severity": "low",
                    "_raw": "Mock alert with alternative field names",
                },
            ]
        )

    def convert_alert_to_detection_data(self, alert: SplunkAlert) -> dict[str, dict]:
        """
        Convert Splunk alert to format expected by OpenBAS detection helper.

        This converts Splunk alert fields to the alert_data format used by
        the _match_alert_elements_original function from pyobas.helpers.

        Args:
            alert: Splunk alert dictionary

        Returns:
            Dictionary in format expected by OpenBAS detection helper:
            {
                "signature_type": {
                    "type": "simple",
                    "data": [list of ip] ,
                }
            }

        Raises:
            SplunkESQueryError: If alert conversion fails
        """
        try:
            detection_data = {}
            alert_dict = alert.model_dump()

            source_ips = self._extract_ip_addresses(
                alert_dict, ["src_ip", "src", "source_ip", "client_ip"]
            )
            if source_ips:
                detection_data[SignatureTypes.SIG_TYPE_SOURCE_IPV4.value] = {
                    "type": "simple",
                    "data": source_ips,
                }

            dest_ips = self._extract_ip_addresses(
                alert_dict, ["dst_ip", "dest", "dest_ip", "destination_ip", "server_ip"]
            )
            if dest_ips:
                detection_data[SignatureTypes.SIG_TYPE_TARGET_IPV4.value] = {
                    "type": "simple",
                    "data": dest_ips,
                }

            self.logger.debug(f"Converted alert to detection data: {detection_data}")
            return detection_data

        except Exception as e:
            raise SplunkESQueryError(f"Failed to convert alert to detection data: {e}") from e

    def _extract_ip_addresses(self, alert: dict, field_names: list[str]) -> list[str]:
        """
        Extract IP addresses from alert using multiple possible field names.

        Args:
            alert: Splunk alert dictionary
            field_names: List of possible field names containing IP addresses

        Returns:
            List of unique IP addresses found
        """
        ips = []
        for field_name in field_names:
            value = alert.get(field_name)
            if value:
                if isinstance(value, list):
                    ips.extend([str(ip) for ip in value if ip])
                else:
                    ips.append(str(value))

        seen = set()
        unique_ips = []
        for ip in ips:
            if ip not in seen:
                seen.add(ip)
                unique_ips.append(ip)

        return unique_ips