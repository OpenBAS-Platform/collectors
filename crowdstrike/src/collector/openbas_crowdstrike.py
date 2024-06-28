from datetime import datetime, timedelta

import pytz
from dateutil.parser import parse
from pyobas.helpers import OpenBASCollectorHelper, OpenBASConfigHelper

from .crowdstrike_api_handler import CrowdstrikeApiHandler


class OpenBASCrowdStrike:
    def __init__(self):
        self.config = OpenBASConfigHelper(
            __file__,
            {
                # API information
                "openbas_url": {"env": "OPENBAS_URL", "file_path": ["openbas", "url"]},
                "openbas_token": {
                    "env": "OPENBAS_TOKEN",
                    "file_path": ["openbas", "token"],
                },
                # Config information
                "collector_id": {
                    "env": "COLLECTOR_ID",
                    "file_path": ["collector", "id"],
                },
                "collector_name": {
                    "env": "COLLECTOR_NAME",
                    "file_path": ["collector", "name"],
                },
                "collector_type": {
                    "env": "COLLECTOR_TYPE",
                    "file_path": ["collector", "type"],
                    "default": "openbas_crowdstream",
                },
                "collector_period": {
                    "env": "COLLECTOR_PERIOD",
                    "file_path": ["collector", "period"],
                },
                "collector_log_level": {
                    "env": "COLLECTOR_LOG_LEVEL",
                    "file_path": ["collector", "log_level"],
                },
                "collector_platform": {
                    "env": "COLLECTOR_PLATFORM",
                    "file_path": ["collector", "platform"],
                },
                # CrowdStrike
                "crowdstrike_client_id": {
                    "env": "CROWDSTRIKE_CLIENT_ID",
                    "file_path": ["crowdstrike", "client_id"],
                    "default": "CHANGEME",
                },
                "crowdstrike_client_secret": {
                    "env": "CROWDSTRIKE_CLIENT_SECRET",
                    "file_path": ["crowdstrike", "client_secret"],
                    "default": "CHANGEME",
                },
                "crowdstrike_api_base_url": {
                    "env": "CROWDSTRIKE_API_BASE_URL",
                    "file_path": ["crowdstrike", "api_base_url"],
                    "default": "https://api.crowdstrike.com",
                },
            },
        )
        self.helper = OpenBASCollectorHelper(
            self.config, open("img/icon-crowdstrike.png", "rb")
        )

        # Initialize CrowdStrike API
        self.crowdstrike_api_handler = CrowdstrikeApiHandler(
            self.helper,
            self.config.get_conf("crowdstrike_client_id"),
            self.config.get_conf("crowdstrike_client_secret"),
            self.config.get_conf("crowdstrike_api_base_url"),
        )

    def _fetch_expectations(self, start_time):
        self.helper.collector_logger.info("Gathering expectations for executed injects")
        expectations = (
            self.helper.api.inject_expectation.expectations_assets_for_source(
                self.config.get_conf("collector_id")
            )
        )
        self.helper.collector_logger.info(
            "Found " + str(len(expectations)) + " expectations waiting to be matched"
        )

        valid_expectations = []

        for expectation in expectations:
            # Parse the creation date of the expectation
            expectation_date = parse(
                expectation["inject_expectation_created_at"]
            ).astimezone(pytz.UTC)

            # Check if the expectation is expired: created date is greater than request start time
            if expectation_date < start_time:
                self.helper.collector_logger.info(
                    f"Expectation expired, failing inject {expectation['inject_expectation_inject']} "
                    f"({expectation['inject_expectation_type']})"
                )
                self.helper.api.inject_expectation.update(
                    expectation["inject_expectation_id"],
                    {
                        "collector_id": self.config.get_conf("collector_id"),
                        "result": (
                            "Not Detected"
                            if expectation["inject_expectation_type"] == "DETECTION"
                            else "Not Prevented"
                        ),
                        "is_success": False,
                    },
                )
            else:
                # Add valid expectations to the list
                valid_expectations.append(expectation)

        return valid_expectations

    def _extract_ip_addresses(self, detections):
        ips = []
        for detection in detections:
            if "device" in detection:
                device = detection["device"]
                if "local_ip" in device:
                    ips.append(device["local_ip"])
                if "external_ip" in device:
                    ips.append(device["external_ip"])
        return ips

    def _match_expectations(self, valid_expectations, start_time):
        try:
            iocs = self.crowdstrike_api_handler.extract_iocs()
            print("iocs :", iocs)
            alerts = self.crowdstrike_api_handler.extract_alerts(start_time)
            print("alerts : ", alerts)
            detections = self.crowdstrike_api_handler.extract_detects(start_time)
            print("detections : ", detections)

            ips = self._extract_ip_addresses(detections)
            print(ips)

            # Logic to match expectations
            for expectation in valid_expectations:
                self.helper.collector_logger.info(
                    f"Processing expectation: {expectation}"
                )
                # Match with detections from cs

        except Exception as e:
            print(f"Error matching expectations: {e}")

    def _process(self):
        """Fetch and match expectations with data from cs"""
        # Calculate the time 45 minutes ago
        now = datetime.now(pytz.UTC)
        start_time = now - timedelta(minutes=15)

        valid_expectations = self._fetch_expectations(start_time)
        self._match_expectations(valid_expectations, start_time)

    def start(self):
        period = self.config.get_conf("collector_period", True, 60)
        self.helper.schedule(self._process, period)
