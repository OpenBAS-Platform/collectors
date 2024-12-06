from datetime import datetime, timedelta

import pytz
from crowdstrike.crowdstrike_api_handler import CrowdstrikeApiHandler
from crowdstrike.pattern_disposition import is_prevented
from crowdstrike.query_strategy.alert import Alert
from crowdstrike.query_strategy.base import Base
from dateutil.parser import parse
from pyobas.helpers import (
    OpenBASCollectorHelper,
    OpenBASConfigHelper,
    OpenBASDetectionHelper,
)
from pyobas.signatures.signature_type import SignatureType
from pyobas.signatures.types import MatchTypes, SignatureTypes


class OpenBASCrowdStrike:
    def __init__(
        self,
        strategy: Base,
        config: OpenBASConfigHelper,
        helper: OpenBASCollectorHelper,
        detection_helper: OpenBASDetectionHelper,
        signature_types,
    ):
        self.strategy = strategy
        self.config = config
        self.helper = helper
        self.detection_helper = detection_helper
        self.signature_types = signature_types

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

    def _match_expectations(self, alerts, expectations):
        for expectation in expectations:
            if expectation.get("inject_expectation_signatures") is None:
                self.helper.collector_logger.warning(
                    f"No expected signatures found in expectation #{expectation.get('id')}"
                )
                continue

            expectation_signatures = expectation.get("inject_expectation_signatures")

            if (
                endpoint_hostname := self.helper.api.endpoint.get(
                    expectation["inject_expectation_asset"]
                ).get("endpoint_hostname")
            ) is not None:
                expectation_signatures += [
                    {
                        "type": SignatureTypes.SIG_TYPE_HOSTNAME.value,
                        "value": endpoint_hostname.lower(),
                    }
                ]

            for alert in alerts:
                if self.detection_helper.match_alert_elements(
                    signatures=expectation_signatures,
                    alert_data=self.strategy.get_signature_data(
                        alert, self.signature_types
                    ),
                ):
                    result: str
                    success_or_failure: bool
                    if expectation.get("inject_expectation_type") == "DETECTION":
                        success_or_failure = True
                        result = "Detected"
                    elif expectation.get("inject_expectation_type") == "PREVENTION":
                        success_or_failure = self.strategy.is_prevented(alert)
                        result = "Prevented" if success_or_failure else "Not prevented"
                    else:
                        self.helper.collector_logger.warning(
                            f"Unsupported expectation type for now: {expectation.get('inject_expectation_type')}"
                        )
                        continue

                    self.helper.api.inject_expectation.update(
                        expectation["inject_expectation_id"],
                        {
                            "collector_id": self.config.get_conf("collector_id"),
                            "result": result,
                            "is_success": success_or_failure,
                            "metadata": {"alertId": alert.get_id()},
                        },
                    )

    def _process(self):
        """Fetch and match expectations with data from cs"""
        now = datetime.now(pytz.UTC)
        start_time = now - timedelta(days=15)

        self._match_expectations(
            alerts=self.strategy.get_raw_data(start_time),
            expectations=self._fetch_expectations(start_time),
        )

    def start(self):
        period = self.config.get_conf("collector_period", True, 60)
        self.helper.schedule(self._process, period)


if __name__ == "__main__":
    config = OpenBASConfigHelper(
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

    helper = OpenBASCollectorHelper(
        config=config,
        icon="crowdstrike/img/icon-crowdstrike.png",
        security_platform_type=config.get_conf("collector_platform"),
    )

    signature_types = [
        SignatureType(
            SignatureTypes.SIG_TYPE_HOSTNAME, match_type=MatchTypes.MATCH_TYPE_SIMPLE
        ),
        SignatureType(
            SignatureTypes.SIG_TYPE_PARENT_PROCESS_NAME,
            match_type=MatchTypes.MATCH_TYPE_FUZZY,
            match_score=95,
        ),
    ]

    detection_helper = OpenBASDetectionHelper(
        helper.collector_logger,
        [signature_type.label for signature_type in signature_types],
    )

    api_handler = CrowdstrikeApiHandler(
        helper=helper,
        client_id=config.get_conf("crowdstrike_client_id"),
        client_secret=config.get_conf("crowdstrike_client_secret"),
        base_url=config.get_conf("crowdstrike_api_base_url"),
    )
    strategy = Alert(api_handler=api_handler)
    collector = OpenBASCrowdStrike(
        strategy=strategy,
        config=config,
        helper=helper,
        detection_helper=detection_helper,
        signature_types=signature_types,
    )
    collector.start()
