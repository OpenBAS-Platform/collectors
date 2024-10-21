import json
import urllib.parse
from datetime import datetime

import pytz
import requests
from dateutil.parser import parse
from dateutil.relativedelta import relativedelta
from pyobas.helpers import (
    OpenBASCollectorHelper,
    OpenBASConfigHelper,
    OpenBASDetectionHelper,
)
from sentinel_api_handler import SentinelApiHandler


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
            config=self.config,
            icon="img/icon-microsoft-sentinel.png",
            security_platform_type="SIEM",
        )

        self.log_analytics_url = "https://api.loganalytics.azure.com/v1"

        # Initialize Sentinel API
        self.sentinel_api_handler = SentinelApiHandler(
            self.helper,
            self.config.get_conf("microsoft_sentinel_tenant_id"),
            self.config.get_conf("microsoft_sentinel_client_id"),
            self.config.get_conf("microsoft_sentinel_client_secret"),
        )

        # Initialize signatures helper
        self.relevant_signatures_types = [
            "process_name",
            "command_line",
            "file_name",
            "hostname",
            "ipv4_address",
            "ipv6_address",
        ]
        self.openbas_detection_helper = OpenBASDetectionHelper(
            self.helper.collector_logger, self.relevant_signatures_types
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

    def _extract_file_names(self, columns_index, alert):
        file_names = []
        entities = json.loads(alert[columns_index["Entities"]])
        for entity in entities:
            if "Type" in entity and entity["Type"] == "process":
                if "ImageFile" in entity and "Name" in entity["ImageFile"]:
                    file_names.append(entity["ImageFile"]["Name"])
            elif "Type" in entity and entity["Type"] == "file":
                file_names.append(entity["Name"])
        return file_names

    def _extract_hostnames(self, columns_index, alert):
        hostnames = []
        entities = json.loads(alert[columns_index["Entities"]])
        for entity in entities:
            if "Type" in entity and entity["Type"] == "dns":
                hostnames.append(entity["DomainName"])
            elif "Type" in entity and entity["Type"] == "url":
                parsed_url = urllib.parse.urlparse(entity["Url"])
                hostnames.append(parsed_url.netloc)
        return hostnames

    def _extract_ip_addresses(self, columns_index, alert):
        ip_addresses = []
        entities = json.loads(alert[columns_index["Entities"]])
        for entity in entities:
            if "Type" in entity and entity["Type"] == "ip":
                ip_addresses.append(entity["Address"])
        return ip_addresses

    def _is_prevented(self, columns_index, alert):
        extended_properties = json.loads(alert[columns_index["ExtendedProperties"]])
        if "Action" in extended_properties and extended_properties["Action"] in [
            "blocked",
            "quarantine",
            "remove",
        ]:
            return True
        return False

    def _match_alert(self, endpoint, columns_index, alert, expectation):
        print(alert)
        self.helper.collector_logger.info(
            "Trying to match alert "
            + str(alert[columns_index["SystemAlertId"]])
            + " with expectation "
            + expectation["inject_expectation_id"]
        )
        # No asset
        if expectation["inject_expectation_asset"] is None:
            return False
        # Check hostname
        hostname = self._extract_device(columns_index, alert)
        if (
            hostname is None
            or hostname.lower() != endpoint["endpoint_hostname"].lower()
        ):
            return False
        self.helper.collector_logger.info(
            "Endpoint is matching (" + endpoint["endpoint_hostname"] + ")"
        )

        alert_data = {}
        for type in self.relevant_signatures_types:
            alert_data[type] = {}
            if type == "process_name":
                alert_data[type] = {
                    "type": "fuzzy",
                    "data": self._extract_process_names(columns_index, alert),
                    "score": 80,
                }
            elif type == "command_line":
                alert_data[type] = {
                    "type": "fuzzy",
                    "data": self._extract_command_lines(columns_index, alert),
                    "score": 60,
                }
            elif type == "file_name":
                alert_data[type] = {
                    "type": "fuzzy",
                    "data": self._extract_file_names(columns_index, alert),
                    "score": 80,
                }
            elif type == "hostname":
                alert_data[type] = {
                    "type": "fuzzy",
                    "data": self._extract_hostnames(columns_index, alert),
                    "score": 80,
                }
            elif type == "ipv4_address":
                alert_data[type] = {
                    "type": "fuzzy",
                    "data": self._extract_ip_addresses(columns_index, alert),
                    "score": 80,
                }
            elif type == "ipv6_address":
                alert_data[type] = {
                    "type": "fuzzy",
                    "data": self._extract_ip_addresses(columns_index, alert),
                    "score": 80,
                }
        match_result = self.openbas_detection_helper.match_alert_elements(
            signatures=expectation["inject_expectation_signatures"],
            alert_data=alert_data,
        )
        if match_result:
            if self._is_prevented(columns_index, alert):
                return "PREVENTED"
            else:
                return "DETECTED"
        return False

    def _process_alerts(self):
        self.helper.collector_logger.info("Gathering expectations for executed injects")
        expectations = (
            self.helper.api.inject_expectation.expectations_assets_for_source(
                self.config.get_conf("collector_id")
            )
        )
        self.helper.collector_logger.info(
            "Found " + str(len(expectations)) + " expectations waiting to be matched"
        )
        limit_date = datetime.now().astimezone(pytz.UTC) - relativedelta(minutes=45)

        # Retrieve alerts
        url = (
            self.log_analytics_url
            + "/workspaces/"
            + self.config.get_conf("microsoft_sentinel_workspace_id")
            + "/query"
        )
        body = {"query": "SecurityAlert | sort by TimeGenerated desc | take 200"}
        data = self.sentinel_api_handler._query(method="post", url=url, payload=body)
        if len(data["tables"]) == 0:
            return
        self.helper.collector_logger.info(
            "Found " + str(len(data["tables"][0]["rows"])) + " alerts"
        )
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
                self.helper.collector_logger.info(
                    "Expectation expired, failing inject "
                    + expectation["inject_expectation_inject"]
                    + " ("
                    + expectation["inject_expectation_type"]
                    + ")"
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
                continue
            endpoint = self.helper.api.endpoint.get(
                expectation["inject_expectation_asset"]
            )
            for alert in data["tables"][0]["rows"]:
                alert_date = parse(
                    str(alert[columns_index["TimeGenerated"]])
                ).astimezone(pytz.UTC)
                print(alert)
                if alert_date > limit_date:
                    result = self._match_alert(
                        endpoint, columns_index, alert, expectation
                    )
                    if result is not False:
                        self.helper.collector_logger.info(
                            "Expectation matched, fulfilling expectation "
                            + expectation["inject_expectation_inject"]
                            + " ("
                            + expectation["inject_expectation_type"]
                            + ")"
                        )
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
