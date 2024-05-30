import json
from datetime import datetime

import pytz
import requests
from dateutil.parser import parse
from dateutil.relativedelta import relativedelta
from pyobas.helpers import OpenBASCollectorHelper, OpenBASConfigHelper
from sentinel_api_handler import SentinelApiHandler
from thefuzz import fuzz


class OpenBASMicrosoftSentinel:
    def __init__(self):
        self.session = requests.Session()
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
                    "default": "openbas_microsoft_sentinel",
                },
                "collector_log_level": {
                    "env": "COLLECTOR_LOG_LEVEL",
                    "file_path": ["collector", "log_level"],
                },
                "collector_period": {
                    "env": "COLLECTOR_PERIOD",
                    "file_path": ["collector", "period"],
                },
                "microsoft_sentinel_tenant_id": {
                    "env": "MICROSOFT_SENTINEL_TENANT_ID",
                    "file_path": ["collector", "microsoft_sentinel_tenant_id"],
                },
                "microsoft_sentinel_client_id": {
                    "env": "MICROSOFT_SENTINEL_CLIENT_ID",
                    "file_path": ["collector", "microsoft_sentinel_client_id"],
                },
                "microsoft_sentinel_client_secret": {
                    "env": "MICROSOFT_SENTINEL_CLIENT_SECRET",
                    "file_path": ["collector", "microsoft_sentinel_client_secret"],
                },
                "microsoft_sentinel_subscription_id": {
                    "env": "MICROSOFT_SENTINEL_SUBSCRIPTION_ID",
                    "file_path": ["collector", "microsoft_sentinel_subscription_id"],
                },
                "microsoft_sentinel_workspace_id": {
                    "env": "MICROSOFT_SENTINEL_WORKSPACE_ID",
                    "file_path": ["collector", "microsoft_sentinel_workspace_id"],
                },
                "microsoft_sentinel_resource_group": {
                    "env": "MICROSOFT_SENTINEL_RESOURCE_GROUP",
                    "file_path": ["collector", "microsoft_sentinel_resource_group"],
                },
            },
        )

        self.helper = OpenBASCollectorHelper(
            self.config, open("img/icon-microsoft-sentinel.png", "rb")
        )

        self.log_analytics_url = "https://api.loganalytics.azure.com/v1"

        # Initialize Sentinel API
        self.sentinel_api_handler = SentinelApiHandler(
            self.helper,
            self.config.get_conf("microsoft_sentinel_tenant_id"),
            self.config.get_conf("microsoft_sentinel_client_id"),
            self.config.get_conf("microsoft_sentinel_client_secret"),
        )

    def _extract_device(self, columns_index, alert):
        entities = json.loads(alert[columns_index["Entities"]])
        for entity in entities:
            if "Type" in entity and entity["Type"] == "host":
                return entity["HostName"]
        return None

    def _extract_process_names(self, columns_index, alert):
        process_names = []
        entities = json.loads(alert[columns_index["Entities"]])
        for entity in entities:
            if "Type" in entity and entity["Type"] == "process":
                if "ImageFile" in entity and "Name" in entity["ImageFile"]:
                    process_names.append(entity["ImageFile"]["Name"])
            elif "Type" in entity and entity["Type"] == "file":
                process_names.append(entity["Name"])
        return process_names

    def _extract_command_lines(self, columns_index, alert):
        command_lines = []
        entities = json.loads(alert[columns_index["Entities"]])
        for entity in entities:
            if "Type" in entity and entity["Type"] == "process":
                command_lines.append(entity["CommandLine"])
        return command_lines

    def _is_prevented(self, columns_index, alert):
        extended_properties = json.loads(alert[columns_index["ExtendedProperties"]])
        if "Action" in extended_properties and extended_properties["Action"] in [
            "blocked",
            "quarantine",
            "remove",
        ]:
            return True
        return False

    def _match_alert(self, columns_index, alert, expectation):
        self.helper.collector_logger.info(
            "Trying to match alert "
            + str(alert[columns_index["SystemAlertId"]])
            + " with expectation "
            + expectation["inject_expectation_id"]
        )
        # No asset
        if expectation["inject_expectation_asset"] is None:
            return False
        endpoint = self.helper.api.endpoint.get(expectation["inject_expectation_asset"])
        # Check hostname
        hostname = self._extract_device(columns_index, alert)
        if hostname is None or hostname != endpoint["endpoint_hostname"]:
            return False
        self.helper.collector_logger.info(
            "Endpoint is matching (" + endpoint["endpoint_hostname"] + ")"
        )
        # Matching logics
        signatures_number = len(expectation["inject_expectation_signatures"])
        matching_number = 0
        # Match signature values to alert
        for signature in expectation["inject_expectation_signatures"]:
            if signature["type"] == "process_name":
                process_names = self._extract_process_names(columns_index, alert)
                for process_name in process_names:
                    self.helper.collector_logger.info(
                        "Comparing process names ("
                        + process_name
                        + ", "
                        + signature["value"]
                        + ")"
                    )
                    ratio = fuzz.ratio(process_name, signature["value"])
                    if ratio > 90:
                        self.helper.collector_logger.info(
                            "MATCHING! (score: " + str(ratio) + ")"
                        )
                        matching_number = matching_number + 1
                        break
            elif signature["type"] == "command_line":
                command_lines = self._extract_command_lines(columns_index, alert)
                if len(command_lines) == 0:
                    matching_number = matching_number + 1
                    break
                for command_line in command_lines:
                    self.helper.collector_logger.info(
                        "Comparing command lines ("
                        + command_line
                        + ", "
                        + signature["value"]
                        + ")"
                    )
                    ratio = fuzz.ratio(command_line, signature["value"])
                    if ratio > 50:
                        self.helper.collector_logger.info(
                            "MATCHING! (score: " + str(ratio) + ")"
                        )
                        matching_number = matching_number + 1
                        break

        if signatures_number == matching_number:
            if self._is_prevented(columns_index, alert):
                return "PREVENTED"
            else:
                return "DETECTED"
        return False

    def _process_alerts(self):
        self.helper.collector_logger.info("Gathering expectations for executed injects")
        expectations = self.helper.api.inject_expectation.expectations_for_source(
            self.config.get_conf("collector_id")
        )
        limit_date = datetime.now().astimezone(pytz.UTC) - relativedelta(minutes=45)

        # Retrieve alerts
        url = (
            self.log_analytics_url
            + "/workspaces/"
            + self.config.get_conf("microsoft_sentinel_workspace_id")
            + "/query"
        )
        body = {"query": "SecurityAlert | sort by TimeGenerated desc"}
        data = self.sentinel_api_handler._query(method="post", url=url, payload=body)
        if len(data["tables"]) == 0:
            return
        columns = data["tables"][0]["columns"]
        columns_index = {}
        for idx, column in enumerate(columns):
            columns_index[column["name"]] = idx
        # For each expectation, try to find the proper alert
        for expectation in expectations:
            # Check expired expectation
            expectation_date = parse(
                expectation["inject_expectation_created_at"]
            ).astimezone(pytz.UTC)
            if expectation_date < limit_date:
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
                continue
            for alert in data["tables"][0]["rows"][:50]:
                alert_date = parse(
                    str(alert[columns_index["TimeGenerated"]])
                ).astimezone(pytz.UTC)
                if alert_date > limit_date:
                    result = self._match_alert(columns_index, alert, expectation)
                    if result is not False:
                        if expectation["inject_expectation_type"] == "DETECTION":
                            self.helper.api.inject_expectation.update(
                                expectation["inject_expectation_id"],
                                {
                                    "collector_id": self.config.get_conf(
                                        "collector_id"
                                    ),
                                    "result": "Detected",
                                    "is_success": True,
                                },
                            )
                        elif (
                            expectation["inject_expectation_type"] == "PREVENTION"
                            and result == "PREVENTED"
                        ):
                            self.helper.api.inject_expectation.update(
                                expectation["inject_expectation_id"],
                                {
                                    "collector_id": self.config.get_conf(
                                        "collector_id"
                                    ),
                                    "result": "Prevented",
                                    "is_success": True,
                                },
                            )

    def _process_message(self) -> None:
        self._process_alerts()

    # Start the main loop
    def start(self):
        period = self.config.get_conf("collector_period", default=120, is_number=True)
        self.helper.schedule(message_callback=self._process_message, delay=period)


if __name__ == "__main__":
    openBASMicrosoftSentinel = OpenBASMicrosoftSentinel()
    openBASMicrosoftSentinel.start()
