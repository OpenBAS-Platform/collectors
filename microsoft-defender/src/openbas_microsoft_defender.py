import asyncio
from datetime import datetime

import pytz
import requests
from azure.identity.aio import ClientSecretCredential
from dateutil.parser import parse
from dateutil.relativedelta import relativedelta
from msgraph import GraphServiceClient
from msgraph.generated.security.alerts_v2.alerts_v2_request_builder import (
    Alerts_v2RequestBuilder,
    RequestConfiguration,
)
from pyobas.helpers import OpenBASCollectorHelper, OpenBASConfigHelper
from thefuzz import fuzz


class OpenBASMicrosoftDefender:
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
                    "default": "openbas_microsoft_defender",
                },
                "collector_log_level": {
                    "env": "COLLECTOR_LOG_LEVEL",
                    "file_path": ["collector", "log_level"],
                },
                "collector_period": {
                    "env": "COLLECTOR_PERIOD",
                    "file_path": ["collector", "period"],
                },
                "microsoft_defender_tenant_id": {
                    "env": "MICROSOFT_DEFENDER_TENANT_ID",
                    "file_path": ["collector", "microsoft_defender_tenant_id"],
                },
                "microsoft_defender_client_id": {
                    "env": "MICROSOFT_DEFENDER_CLIENT_ID",
                    "file_path": ["collector", "microsoft_defender_client_id"],
                },
                "microsoft_defender_client_secret": {
                    "env": "MICROSOFT_DEFENDER_CLIENT_SECRET",
                    "file_path": ["collector", "microsoft_defender_client_secret"],
                },
            },
        )
        self.helper = OpenBASCollectorHelper(
            self.config, open("img/icon-microsoft-defender.png", "rb")
        )

    def _extract_device(self, alert):
        for evidence in alert.evidence:
            if evidence.odata_type == "#microsoft.graph.security.deviceEvidence":
                return evidence.device_dns_name
        return None

    def _extract_process_names(self, alert):
        process_names = []
        for evidence in alert.evidence:
            if evidence.odata_type == "#microsoft.graph.security.processEvidence":
                process_names.append(evidence.image_file.file_name)
            elif evidence.odata_type == "#microsoft.graph.security.fileEvidence":
                process_names.append(evidence.file_details.file_name)
        return process_names

    def _extract_command_lines(self, alert):
        command_lines = []
        for evidence in alert.evidence:
            if evidence.odata_type == "#microsoft.graph.security.processEvidence":
                command_lines.append(evidence.process_command_line)
        return command_lines

    def _is_prevented(self, alert):
        for evidence in alert.evidence:
            if evidence.odata_type == "#microsoft.graph.security.processEvidence":
                if evidence.detection_status in [
                    "prevented",
                    "remediated",
                    "blocked",
                ]:
                    return True
        return False

    def _match_alert(self, endpoint, alert, expectation):
        self.helper.collector_logger.info(
            "Trying to match alert "
            + str(alert.id)
            + " with expectation "
            + expectation["inject_expectation_id"]
        )
        # No asset
        if expectation["inject_expectation_asset"] is None:
            return False
        # Check hostname
        hostname = self._extract_device(alert)
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
                process_names = self._extract_process_names(alert)
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
                command_lines = self._extract_command_lines(alert)
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
                    # TODO Get the proper command line from Defender in the remediation action
                    # ratio = fuzz.ratio(command_line, signature["value"])
                    ratio = 100
                    if ratio > 50:
                        self.helper.collector_logger.info(
                            "MATCHING! (score: " + str(ratio) + ")"
                        )
                        matching_number = matching_number + 1
                        break

        if signatures_number == matching_number:
            if self._is_prevented(alert):
                return "PREVENTED"
            else:
                return "DETECTED"
        return False

    async def _process_alerts(self, graph_client):
        self.helper.collector_logger.info("Gathering expectations for executed injects")
        expectations = self.helper.api.inject_expectation.expectations_for_source(
            self.config.get_conf("collector_id")
        )
        self.helper.collector_logger.info(
            "Found " + str(len(expectations)) + " expectations waiting to be matched"
        )
        limit_date = datetime.now().astimezone(pytz.UTC) - relativedelta(minutes=45)
        query_params = (
            Alerts_v2RequestBuilder.Alerts_v2RequestBuilderGetQueryParameters(
                orderby=["createdDateTime DESC"], top=200
            )
        )
        request_configuration = RequestConfiguration(query_parameters=query_params)
        alerts = await graph_client.security.alerts_v2.get(
            request_configuration=request_configuration
        )
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
            self.helper.collector_logger.info(
                "Found " + str(len(alerts.value)) + " alerts"
            )
            endpoint = self.helper.api.endpoint.get(
                expectation["inject_expectation_asset"]
            )
            for i in range(len(alerts.value)):
                alert = alerts.value[i]
                alert_date = parse(str(alert.created_date_time)).astimezone(pytz.UTC)
                if alert_date > limit_date:
                    result = self._match_alert(endpoint, alert, expectation)
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
        # Auth
        scopes = ["https://graph.microsoft.com/.default"]
        credential = ClientSecretCredential(
            tenant_id=self.config.get_conf("microsoft_defender_tenant_id"),
            client_id=self.config.get_conf("microsoft_defender_client_id"),
            client_secret=self.config.get_conf("microsoft_defender_client_secret"),
        )
        graph_client = GraphServiceClient(credential, scopes=scopes)  # type: ignore

        # Execute
        loop = asyncio.get_event_loop()
        loop.run_until_complete(self._process_alerts(graph_client))

    # Start the main loop
    def start(self):
        period = self.config.get_conf("collector_period", default=120, is_number=True)
        self.helper.schedule(message_callback=self._process_message, delay=period)


if __name__ == "__main__":
    openBASMicrosoftDefender = OpenBASMicrosoftDefender()
    openBASMicrosoftDefender.start()
