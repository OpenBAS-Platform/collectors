import asyncio
import json
from datetime import datetime

import pytz
import requests
from azure.identity.aio import ClientSecretCredential
from dateutil.parser import parse
from dateutil.relativedelta import relativedelta
from msgraph import GraphServiceClient
from msgraph.generated.security.microsoft_graph_security_run_hunting_query.run_hunting_query_post_request_body import (
    RunHuntingQueryPostRequestBody,
)
from pyobas.helpers import (
    OpenBASCollectorHelper,
    OpenBASConfigHelper,
    OpenBASDetectionHelper,
)

# This is the "god query" that aggregates a bunch of alert-related data
# distributed in various tables within the Microsoft Defender saas.
# Most `let` statements act as enriching staging tables for later
# joining together. We currently only consider File and Process
# evidence types (see `let fileEvidence` and `let processEvidence`).
#
# To correlate File evidence with a process tree: we search for
# file activity in both DeviceEvents and DeviceFileEvents.
# This way we are able to determine a process that interacted with the
# file (often creating it). For some reason, not all file activity is
# logged in DeviceFileEvents.
# Using this data, we join onto the File evidence records using the
# file's name and folder path (could have been a full path). This
# allows for linking a File evidence with a given origin process.
#
# Process evidence a more straightforward: the process information is
# contained directly within the evidence data.
#
# We then compute a process tree using recorded process activity, and
# project a graph that links any process with each of its ancestors.
# The tree is proactively trimmed to only keep records that found
# "obas-implant*" as an ancestor process.
#
# Joining evidence records, enriched with an originating process info,
# with the tree allows for correlating an evidence record with a
# specific obas-implant-<inject uuid> process, allowing for inferring
# that a given evidence was generated by a specific inject.
#
# The data is then formatted for use by the api caller: a given api
# record has a collection of `evidence` and the schema for those is
# inferred by the arguments to `bag_pack_columns` in the query.
#
#   There is an available sandbox at https://security.microsoft.com/v2/advanced-hunting
#   You may copy/paste this query as-is and fiddle with it.
#   However, do mind the escaping of the backslashes in the normalisePath function
#   In python it's four backslashes for escaping: replace_string(pathString, "\\\\", "/")
#   In the sandbox UI: two backslashes: replace_string(pathString, "\\", "/")
#
TH_API_QUERY = """
let normalisePath = (pathString:string) { tolower(trim_end("/", replace_string(pathString, "\\\\", "/"))); };
let augmentedDeviceEvents = DeviceEvents
    | where isnotnull(InitiatingProcessId) and InitiatingProcessId != 0
    | extend normalised_filename=normalisePath(FileName),
             normalised_folder_path=normalisePath(FolderPath),
             process_hash=hash(strcat(DeviceId, InitiatingProcessId, normalisePath(InitiatingProcessFileName), InitiatingProcessCreationTime))
    | project DeviceId, normalised_filename, normalised_folder_path, process_hash;
let augmentedFileEvents = DeviceFileEvents
    | extend normalised_filename=normalisePath(FileName),
             normalised_folder_path=normalisePath(parse_path(FolderPath).DirectoryPath),
             process_hash=hash(strcat(DeviceId, InitiatingProcessId, normalisePath(InitiatingProcessFileName), InitiatingProcessCreationTime))
    | project DeviceId, normalised_filename, normalised_folder_path, process_hash;
let augmentedAllFilesEvents = augmentedDeviceEvents
    | union augmentedFileEvents
    | distinct DeviceId, normalised_filename, normalised_folder_path, process_hash;
let singleMachinePerAlert = AlertEvidence
    | where EntityType has "Machine" and EvidenceRole has "Impacted"
    | summarize max(TimeGenerated) by AlertId, DeviceId, DeviceName;
let fileEvidence = singleMachinePerAlert
    | join AlertEvidence on $left.AlertId == $right.AlertId
    | where EntityType has "File"
    | extend normalised_filename=normalisePath(FileName), normalised_folder_path=normalisePath(FolderPath), d=parse_json(AdditionalFields)
    | join kind=inner augmentedAllFilesEvents on $left.DeviceId == $right.DeviceId and $left.normalised_filename == $right.normalised_filename and $left.normalised_folder_path == $right.normalised_folder_path
    | project AlertId, EntityType, DeviceId, DeviceName, Identifier=normalised_filename, LastRemediationState=d.LastRemediationState, DetectionStatus=d.DetectionStatus, normalised_folder_path, process_hash;
let processEvidence = singleMachinePerAlert
    | join AlertEvidence on $left.AlertId == $right.AlertId
    | where EntityType has "Process"
    | extend normalised_filename=normalisePath(FileName), d=parse_json(AdditionalFields)
    | extend process_hash=hash(strcat(DeviceId, d.ProcessId, normalised_filename, todatetime(d.CreationTimeUtc)))
    | project AlertId, EntityType, DeviceId, DeviceName, Identifier=normalised_filename, LastRemediationState=d.LastRemediationState, DetectionStatus=d.DetectionStatus, normalised_folder_path="<empty>", process_hash;
let hashedProcessEvents = DeviceProcessEvents
    | extend process_hash = hash(strcat(DeviceId, ProcessId, normalisePath(FileName), ProcessCreationTime)), parent_hash = hash(strcat(DeviceId, InitiatingProcessId, normalisePath(InitiatingProcessFileName), InitiatingProcessCreationTime));
let tree = hashedProcessEvents
    | join kind=leftouter hashedProcessEvents on $left.parent_hash == $right.process_hash
    | make-graph process_hash --> process_hash1 with hashedProcessEvents on process_hash
    | graph-match (parent)<-[spawnedBy*1..100]-(child)
        where parent.FileName startswith "obas-implant" or child.FileName startswith "obas-implant"
        project child.process_hash, child.ProcessId, child.FileName, child.ProcessCommandLine, child.ProcessCreationTime, parent.ProcessId, parent.FileName, parent.ProcessCommandLine, parent.ProcessCreationTime, Path = strcat(spawnedBy.ProcessId, " ", spawnedBy.ProcessCommandLine)
    | extend PathLength = array_length(Path);
fileEvidence
| union processEvidence
| join kind=inner tree on $left.process_hash == $right.child_process_hash
| project-rename ParentProcessImageFileName=parent_FileName, CommandLine=child_ProcessCommandLine
| extend data=bag_pack_columns(EntityType, Identifier, LastRemediationState, DetectionStatus, ParentProcessImageFileName, CommandLine)
| summarize evidence=make_list(data) by AlertId, DeviceName
"""


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
            self.config,
            "img/icon-microsoft-defender.png",
            security_platform_type="EDR",
        )

        # Initialize signatures helper
        self.relevant_signatures_types = [
            "parent_process_name",
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

    def _extract_device(self, alert):
        return alert.get("DeviceName", None)

    def _extract_parent_process_names(self, evidences):
        return [
            evidence.get("ParentProcessImageFileName")
            for evidence in evidences
            if evidence.get("EntityType") in ["Process", "File"]
        ]

    def _extract_process_names(self, evidences):
        # Return both the actual process name and those of the found parents.
        # Some executors are intercepted with the signature process name
        # either being a child process ("process_name") or a parent process.
        # Apparently this may happen if the inject is detected but not prevented
        return [
            process_name
            for evidence in evidences
            if evidence.get("EntityType") in ["Process", "File"]
            for process_name in [
                evidence.get("Identifier"),
                evidence.get("ParentProcessImageFileName"),
            ]
        ]

    def _extract_command_lines(self, evidences):
        return [
            evidence.get("CommandLine")
            for evidence in evidences
            if evidence.get("EntityType") == "Process"
        ]

    def _extract_file_names(self, evidences):
        return [
            evidence.get("Identifier")
            for evidence in evidences
            if evidence.get("EntityType") == "File"
        ]

    def _extract_hostnames(self, evidences):
        return [
            evidence.get("Identifier")
            for evidence in evidences
            if evidence.get("EntityType") == "Url"
        ]

    def _extract_ip_addresses(self, evidences):
        return [
            evidence.get("Identifier")
            for evidence in evidences
            if evidence.get("EntityType") == "Ip"
        ]

    def _is_prevented(self, evidences):
        return any(
            [
                evidence.get("LastRemediationState")
                for evidence in evidences
                if evidence.get("LastRemediationState")
                in ["Prevented", "Blocked", "Remediated"]
            ]
        )

    def _match_alert(self, endpoint, alert, expectation):
        self.helper.collector_logger.info(
            "Trying to match alert "
            + str(alert.get("AlertId"))
            + " with expectation "
            + expectation["inject_expectation_id"]
        )

        # No asset
        if expectation["inject_expectation_asset"] is None:
            return False

        # Check hostname
        hostname = self._extract_device(alert)
        if (
            hostname is None
            or hostname.lower() != endpoint["endpoint_hostname"].lower()
        ):
            return False
        self.helper.collector_logger.info(
            "Endpoint is matching (" + endpoint["endpoint_hostname"] + ")"
        )

        alert_data = {}
        evidences = [json.loads(evidence) for evidence in alert.get("evidence")]
        for signature_type in self.relevant_signatures_types:
            alert_data[signature_type] = {}
            if signature_type == "parent_process_name":
                alert_data[signature_type] = {
                    "type": "fuzzy",
                    "data": self._extract_parent_process_names(evidences),
                    "score": 95,
                }
            elif signature_type == "process_name":
                alert_data[signature_type] = {
                    "type": "simple",
                    "data": self._extract_process_names(evidences),
                }
            elif signature_type in ["command_line", "command_line_base64"]:
                alert_data[signature_type] = {
                    "type": "fuzzy",
                    "data": self._extract_command_lines(evidences),
                    "score": 60,
                }
            elif signature_type == "file_name":
                alert_data[signature_type] = {
                    "type": "fuzzy",
                    "data": self._extract_file_names(evidences),
                    "score": 80,
                }
            elif signature_type == "hostname":
                alert_data[signature_type] = {
                    "type": "fuzzy",
                    "data": self._extract_hostnames(evidences),
                    "score": 80,
                }
            elif signature_type in ["ipv4_address", "ipv6_address"]:
                alert_data[signature_type] = {
                    "type": "fuzzy",
                    "data": self._extract_ip_addresses(evidences),
                    "score": 80,
                }
        match_result = self.openbas_detection_helper.match_alert_elements(
            signatures=[
                {
                    "type": expectation.get("type"),
                    # the KQL query lowers all, filenames due to limitation in data source
                    # therefore we need to compare to lowercased strings
                    "value": expectation.get("value").lower(),
                }
                for expectation in expectation["inject_expectation_signatures"]
            ],
            alert_data=alert_data,
        )
        if match_result:
            if self._is_prevented(evidences):
                return "PREVENTED"
            else:
                return "DETECTED"
        return False

    async def _process_alerts(self, graph_client):
        self.helper.collector_logger.info("Gathering expectations for executed injects")
        expectations = (
            self.helper.api.inject_expectation.expectations_assets_for_source(
                self.config.get_conf("collector_id")
            )
        )
        self.helper.collector_logger.info(
            "Found " + str(len(expectations)) + " expectations waiting to be matched"
        )

        if not any(expectations):
            self.helper.collector_logger.info(
                "No expectations found: skipping iteration."
            )
            return

        limit_date = datetime.now().astimezone(pytz.UTC) - relativedelta(minutes=45)
        alerts = (
            await graph_client.security.microsoft_graph_security_run_hunting_query.post(
                body=RunHuntingQueryPostRequestBody(
                    query=TH_API_QUERY, timespan=str(limit_date)
                )
            )
        )
        self.helper.collector_logger.info(
            "Found " + str(len(alerts.results)) + " alerts with signatures"
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
            endpoint = self.helper.api.endpoint.get(
                expectation["inject_expectation_asset"]
            )
            for alert in alerts.results:
                if result := self._match_alert(
                    endpoint, alert.additional_data, expectation
                ):
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
                                "collector_id": self.config.get_conf("collector_id"),
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
                                "collector_id": self.config.get_conf("collector_id"),
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
