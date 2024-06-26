from datetime import datetime

import pytz
from dateutil.parser import parse
from dateutil.relativedelta import relativedelta

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

    def _fetch_expectations(self):
        self.helper.collector_logger.info("Gathering expectations for executed injects")
        expectations = (
            self.helper.api.inject_expectation.expectations_assets_for_source(
                self.config.get_conf("collector_id")
            )
        )
        self.helper.collector_logger.info(
            "Found " + str(len(expectations)) + " expectations waiting to be matched"
        )
        limit_date = datetime.now().astimezone(pytz.UTC) - relativedelta(days=45)

        valid_expectations = []

        for expectation in expectations:
            # Parse the creation date of the expectation
            expectation_date = parse(
                expectation["inject_expectation_created_at"]
            ).astimezone(pytz.UTC)

            # Check if the expectation is expired
            if expectation_date < limit_date:
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

    def _match_expectations(self, valid_expectations):
        try:
            iocs = self.crowdstrike_api_handler.extract_iocs()
            print(iocs)
            # Process alerts and incidents if needed
        except Exception as e:
            print(f"Error matching expectations: {e}")

    # Implement the logic to match expectations
        for expectation in valid_expectations:
            self.helper.collector_logger.info(f"Processing expectation: {expectation}")
            # Add your processing logic here

    def _process(self):
        """Fetch and match expectations with data from cs"""
        valid_expectations = self._fetch_expectations()
        self._match_expectations(valid_expectations)

    def start(self):
        period = self.config.get_conf("collector_period", True, 60)
        self.helper.schedule(self._process, period)
