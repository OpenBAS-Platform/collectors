from datetime import datetime, timedelta

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

SENTINEL_QUERY = """
        let SubscriptionId = "{subscription_id}";
        let ResourceGroup = "{resource_group}";}";
        let WorkspaceName = "{workspace_name}";
        let WorkspaceId = strcat("/subscriptions/", SubscriptionId, "/resourceGroups/", ResourceGroup, 
                                "/providers/Microsoft.OperationalInsights/workspaces/", WorkspaceName);
        let SentinelBaseUrl = "https://portal.azure.com/#blade/Microsoft_Azure_Security_Insights/";
        SecurityAlert
        | where StartTime between (datetime({start_time}) .. datetime({end_time}))}))
        | project
            SystemAlertId,
            AlertName,
            StartTime,
            EndTime,
            TimeGenerated,
            Entities,
            ProviderName,
            VendorName,
            ProductName
        | extend Entities = parse_json(Entities)
        | extend ParsedEntities = Entities
        | mv-expand ParsedEntities
        | extend EntityType = tostring(ParsedEntities.Type)
        | summarize 
            IPAddresses = make_set_if(tostring(ParsedEntities.Address), EntityType == "ip"),
            Hostnames = make_set_if(tostring(ParsedEntities.HostName), EntityType == "host"),
            ProcessNames = make_set_if(tostring(ParsedEntities.Name), EntityType == "process"),
            ProcessIds = make_set_if(tostring(ParsedEntities.ProcessId), EntityType == "process"),
            Filenames = make_set_if(tostring(ParsedEntities.Name), EntityType == "file"),
            // Keep all original fields to prevent duplicates
            take_any(TimeGenerated, AlertName, ProviderName, VendorName, ProductName, Entities, StartTime, EndTime)
            by SystemAlertId  // Group ONLY by SystemAlertId to ensure uniqueness
        | extend 
            IPAddress = strcat_array(IPAddresses, ", "),
            Hostname = strcat_array(Hostnames, ", "),
            ProcessName = strcat_array(ProcessNames, ", "),
            ProcessId = strcat_array(ProcessIds, ", "),
            Filename = strcat_array(Filenames, ", "),
            AlertLink = strcat(SentinelBaseUrl, "AlertBlade/alertId/", SystemAlertId, WorkspaceId)
        | join kind=leftouter (
            SecurityIncident
            | mv-expand AlertIds = parse_json(AlertIds)
            | extend AlertId = tostring(AlertIds)
            | summarize take_any(IncidentNumber, IncidentUrl, Title, Status, Severity) by AlertId  // Deduplicate here too
            )
            on $left.SystemAlertId == $right.AlertId
        | extend HasIncident = isnotempty(IncidentNumber)
        | project
            TimeGenerated,
            StartTime,
            EndTime,
            AlertName,
            IPAddress,
            Hostname,
            ProcessName,
            Filename, 
            IncidentUrl,
            AlertLink,
            SystemAlertId,
            HasIncident
        | order by TimeGenerated desc
        """
TIME_DELTA_FOR_EXPECTATIONS = 500 # milliseconds

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
                "microsoft_sentinel_edr_collectors": {
                    "env": "MICROSOFT_SENTINEL_EDR_COLLECTORS",
                    "file_path": ["collector", "microsoft_sentinel_edr_collectors"],
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
            "parent_process_name",
        ]
        self.openbas_detection_helper = OpenBASDetectionHelper(
            self.helper.collector_logger, self.relevant_signatures_types
        )

        self.scanning_delta = 45

    # --- EXTRACTOR ---

    def _extract_alert_link(self, columns_index, alert):
        alert_link = []
        # Direct Alert Link
        alert_link.append(alert[columns_index["AlertLink"]])
        # Extended Alert Link
        if "ExtendedLinks" in alert:
            for link in alert["ExtendedLinks"]:
                if "Href" in link:
                    alert_link.append(link["Href"])
        return alert_link

    def _extract_alert_name(self, columns_index, alert):
        display_name = [alert[columns_index["DisplayName"]]]
        return display_name

    def _extract_alert_detection_date(self, columns_index, alert):
        detection_date = [alert[columns_index["StartTime"]]]
        return detection_date

    def _extract_alert_prevention_date(self, columns_index, alert):
        prevention_date = [alert[columns_index["EndTime"]]]
        return prevention_date

    # --- MATCHING ---

    def _get_time_range_from_expectations(self, expectations):
        earliest_start = None
        latest_end = None

        for expectation in expectations:
            status = expectation["inject"]["inject_status"]

            if status["tracking_sent_date"] is not None:
                start_time = parse(status["tracking_sent_date"]).astimezone(pytz.UTC)
                if earliest_start is None or start_time < earliest_start:
                    earliest_start = start_time

            if status["tracking_end_date"] is not None:
                end_time = parse(status["tracking_end_date"]).astimezone(pytz.UTC)
                if latest_end is None or end_time > latest_end:
                    latest_end = end_time

        # Adjust times with deltas
        buffer = timedelta(milliseconds=TIME_DELTA_FOR_EXPECTATIONS)
        if earliest_start is not None:
            earliest_start = earliest_start - buffer
        if latest_end is not None:
            latest_end = latest_end + buffer

        return earliest_start, latest_end

    def _is_prevented(self, columns_index, alert):
        prevented_keywords = ["blocked", "quarantine", "remove", "prevented"]
        alert_name = alert[columns_index["AlertName"]].strip().lower()
        result_alert_name = any(
            prevented_keyword in alert_name for prevented_keyword in prevented_keywords
        )
        return result_alert_name

    def _match_alert_link(self, expectation, alert_link_datas) -> bool:
        # Extract expectation alert link
        alert_id_expectation = None
        status_start_time = parse(expectation["inject"]["inject_status"]["tracking_sent_date"]).astimezone(pytz.UTC)
        status_end_time = parse(expectation["inject"]["inject_status"]["tracking_end_date"]).astimezone(pytz.UTC)
        IPs = expectation["asset"]["endpoint_ips"]
        hostname = expectation["asset"]["endpoint_hostnames"]
        if (alert_link_datas["IPAddress"] in IPs) or (alert_link_datas["Hostname"] == hostname):
            # expectation and alert are on the same asset, we then need to check the time range to make sure they correspond to the same inject
            alert_start_time = alert_link_datas["StartTime"]
            alert_end_time = alert_link_datas["EndTime"]
            buffer = timedelta(milliseconds=TIME_DELTA_FOR_EXPECTATIONS)
            if (alert_start_time >= status_start_time - buffer) and (alert_end_time <= status_end_time + buffer):
                return True
        return False

    def _match_alert_from_edr(self, _endpoint, columns_index, alert, expectation):
        self.helper.collector_logger.info(
            "Trying to match alert from EDR"
            + str(alert[columns_index["SystemAlertId"]])
            + " with expectation "
            + expectation["inject_expectation_id"]
        )
        match_result = self._match_alert_link(
            expectation=expectation,
            alert_link_datas=self._extract_alert_link(columns_index, alert),
        )
        if match_result:
            if self._is_prevented(columns_index, alert):
                return "PREVENTED"
            else:
                return "DETECTED"
        return False

    # --- PROCESS ---

    def _is_expectation_filled(self, expectation) -> bool:
        return any(
            er.get("sourceId", "") == self.config.get_conf("collector_id")
            for er in expectation["inject_expectation_results"]
        )

    def _process_alerts(self):
        self.helper.collector_logger.info("Gathering expectations for executed injects")
        expectations = (
            self.helper.api.inject_expectation.expectations_assets_for_source(
                self.config.get_conf("collector_id"),
                self.scanning_delta,
            )
        )
        self.helper.collector_logger.debug(
            "Total expectations returned: " + str(len(expectations))
        )
        expectations_not_filled = list(
            filter(
                lambda expectation: not self._is_expectation_filled(expectation),
                expectations,
            )
        )
        self.helper.collector_logger.info(
            "Found "
            + str(len(expectations_not_filled))
            + " expectations waiting to be matched"
        )
        limit_date = datetime.now().astimezone(pytz.UTC) - relativedelta(
            minutes=self.scanning_delta
        )

        # Get the time range for expectations, to use in the KQL query
        earliest_start, latest_end = self._get_time_range_from_expectations(expectations)

        # Retrieve alerts
        url = (
            self.log_analytics_url
            + "/workspaces/"
            + self.config.get_conf("microsoft_sentinel_workspace_id")
            + "/query"
        )

        query = SENTINEL_QUERY.format(
            subscription_id=self.config.get_conf("microsoft_sentinel_subscription_id"),
            resource_group=self.config.get_conf("microsoft_sentinel_resource_group"),
            workspace_name=self.config.get_conf("microsoft_sentinel_workspace_id"),
            start_time=earliest_start.strftime("%Y-%m-%dT%H:%M:%SZ"),
            end_time=latest_end.strftime("%Y-%m-%dT%H:%M:%SZ"),
        )
        data = self.sentinel_api_handler._query(method="post", url=url, payload={"query": query})

        if len(data["tables"]) == 0:
            return
        self.helper.collector_logger.info(
            "Found " + str(len(data["tables"][0]["rows"])) + " alerts"
        )
        columns = data["tables"][0]["columns"]
        columns_index = {}
        for idx, column in enumerate(columns):
            columns_index[column["name"]] = idx

        endpoint_per_asset = {}

        # For each expectation, try to find the proper alert to assign a detection or prevention result
        for expectation in expectations:
            if expectation["inject_expectation_asset"] not in endpoint_per_asset:
                endpoint_per_asset[expectation["inject_expectation_asset"]] = (
                    self.helper.api.endpoint.get(
                        expectation["inject_expectation_asset"]
                    )
                )

            if expectation in expectations_not_filled:
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
                    expectations_not_filled.remove(expectation)
                    continue

            for alert in data["tables"][0]["rows"]:
                alert_date = parse(
                    str(alert[columns_index["TimeGenerated"]])
                ).astimezone(pytz.UTC)
                if alert_date > limit_date:
                    result = self._match_alert_from_edr(
                        endpoint_per_asset[expectation["inject_expectation_asset"]],
                        columns_index,
                        alert,
                        expectation,
                    )
                    if result is not False:
                        if expectation in expectations_not_filled:
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
                            expectations_not_filled.remove(expectation)

                        # Send alert to openbas for current matched expectation. Duplicate alerts are handled by openbas itself
                        self.helper.collector_logger.info(
                            "Expectation matched, adding trace for expectation "
                            + expectation["inject_expectation_inject"]
                            + " ("
                            + expectation["inject_expectation_type"]
                            + ")"
                        )
                        self.helper.api.inject_expectation_trace.create(
                            data={
                                "inject_expectation_trace_expectation": expectation[
                                    "inject_expectation_id"
                                ],
                                "inject_expectation_trace_source_id": self.config.get_conf(
                                    "collector_id"
                                ),
                                "inject_expectation_trace_alert_name": self._extract_alert_name(
                                    columns_index, alert
                                )[
                                    0
                                ],
                                "inject_expectation_trace_alert_link": self._extract_alert_link(
                                    columns_index, alert
                                )[
                                    0
                                ],
                                "inject_expectation_trace_date": self._extract_alert_detection_date(
                                    columns_index, alert
                                )[
                                    0
                                ],
                            }
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

# Avoir un bandeau pour limiter la casse: quand on a Sentinel qui tourne sans Defender -> ça ne marche pas
