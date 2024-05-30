import json
from datetime import datetime

import pytz
import requests
from dateutil.parser import parse
from dateutil.relativedelta import relativedelta
from pyobas.helpers import OpenBASCollectorHelper, OpenBASConfigHelper
from tanium_api_handler import TaniumApiHandler
from thefuzz import fuzz


class OpenBASTaniumThreatResponse:
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
                    "default": "openbas_tanium_threat_response",
                },
                "collector_log_level": {
                    "env": "COLLECTOR_LOG_LEVEL",
                    "file_path": ["collector", "log_level"],
                },
                "collector_period": {
                    "env": "COLLECTOR_PERIOD",
                    "file_path": ["collector", "period"],
                },
                "tanium_url": {
                    "env": "TANIUM_URL",
                    "file_path": ["collector", "tanium_url"],
                },
                "tanium_url_console": {
                    "env": "TANIUM_URL_CONSOLE",
                    "file_path": ["collector", "tanium_url_console"],
                },
                "tanium_ssl_verify": {
                    "env": "TANIUM_SSL_VERIFY",
                    "file_path": ["collector", "tanium_ssl_verify"],
                },
                "tanium_token": {
                    "env": "TANIUM_TOKEN",
                    "file_path": ["collector", "tanium_token"],
                },
            },
        )
        self.helper = OpenBASCollectorHelper(
            self.config, open("img/icon-tanium.png", "rb")
        )

        # Initialize Tanium API
        self.tanium_api_handler = TaniumApiHandler(
            self.helper,
            self.config.get_conf("tanium_url"),
            self.config.get_conf("tanium_token"),
            self.config.get_conf("tanium_ssl_verify"),
        )

    # Recursive function
    def _extract_tree_names(self, artifact, names):
        if (
            "process" in artifact
            and "file" in artifact["process"]
            and "file" in artifact["process"]["file"]
        ):
            names.append(artifact["process"]["file"]["file"]["path"].split("\\")[-1])
        if "process" in artifact and "parent" in artifact["process"]:
            return self._extract_tree_names(artifact["process"]["parent"], names)
        else:
            return names

    def _extract_process_names(self, alert_details):
        process_names = []
        if "finding" in alert_details and "whats" in alert_details["finding"]:
            for what in alert_details["finding"]["whats"]:
                if (
                    "artifact_activity" in what
                    and "acting_artifact" in what["artifact_activity"]
                ):
                    acting_artifact = what["artifact_activity"]["acting_artifact"]
                    process_names = self._extract_tree_names(
                        acting_artifact, process_names
                    )
        return process_names

    # Recursive function
    def _extract_tree_commands(self, artifact, commands):
        if "process" in artifact and "arguments" in artifact["process"]:
            file_path = ""
            if "file" in artifact["process"] and "file" in artifact["process"]["file"]:
                file_path = artifact["process"]["file"]["file"]["path"]
            command = (
                artifact["process"]["arguments"]
                .replace(file_path, "")
                .replace('""', "")
                .strip()
            )
            if len(command) > 0:
                commands.append(command)
        if "process" in artifact and "parent" in artifact["process"]:
            return self._extract_tree_commands(artifact["process"]["parent"], commands)
        else:
            return commands

    def _extract_command_lines(self, alert_details):
        command_lines = []
        if "finding" in alert_details and "whats" in alert_details["finding"]:
            for what in alert_details["finding"]["whats"]:
                if (
                    "artifact_activity" in what
                    and "acting_artifact" in what["artifact_activity"]
                ):
                    acting_artifact = what["artifact_activity"]["acting_artifact"]
                    command_lines = self._extract_tree_commands(
                        acting_artifact, command_lines
                    )
        return command_lines

    def _match_alert(self, alert, expectation):
        alert_details = json.loads(alert["details"])
        self.helper.collector_logger.info(
            "Trying to match alert "
            + str(alert["id"])
            + " with expectation "
            + expectation["inject_expectation_id"]
        )
        # No asset
        if expectation["inject_expectation_asset"] is None:
            return False
        # Defender / Deep Instinct (dedicated collectors)
        if alert["matchType"] in ["windows_defender", "deep_instinct"]:
            return False
        endpoint = self.helper.api.endpoint.get(expectation["inject_expectation_asset"])
        # Check hostname
        if endpoint["endpoint_hostname"] != alert["computerName"]:
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
                process_names = self._extract_process_names(alert_details)
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
                command_lines = self._extract_command_lines(alert_details)
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
            return True
        return False

    def _process_message(self) -> None:
        self.helper.collector_logger.info("Gathering expectations for executed injects")
        expectations = (
            self.helper.api.inject_expectation.detection_expectations_for_source(
                self.config.get_conf("collector_id")
            )
        )
        alerts = self.tanium_api_handler._query(
            "get",
            "/plugin/products/threat-response/api/v1/alerts",
            {"sort": "-createdAt"},
        )
        limit_date = datetime.now().astimezone(pytz.UTC) - relativedelta(minutes=45)
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
                        "result": "Not Detected",
                        "is_success": False,
                    },
                )
                continue
            for alert in alerts:
                alert_date = parse(alert["createdAt"]).astimezone(pytz.UTC)
                if alert_date > limit_date and alert["state"] != "suppressed":
                    if self._match_alert(alert, expectation):
                        self.helper.api.inject_expectation.update(
                            expectation["inject_expectation_id"],
                            {
                                "collector_id": self.config.get_conf("collector_id"),
                                "result": "Detected",
                                "is_success": True,
                            },
                        )

    # Start the main loop
    def start(self):
        period = self.config.get_conf("collector_period", default=120, is_number=True)
        self.helper.schedule(message_callback=self._process_message, delay=period)


if __name__ == "__main__":
    openBASTaniumThreatResponse = OpenBASTaniumThreatResponse()
    openBASTaniumThreatResponse.start()
