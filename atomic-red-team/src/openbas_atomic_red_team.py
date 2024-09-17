import requests
import yaml
from pyobas.helpers import OpenBASCollectorHelper, OpenBASConfigHelper

ATOMIC_RED_TEAM_INDEX = "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/Indexes/index.yaml"

VERIFIED_PAYLOADS = ["aa6cb8c4-b582-4f8e-b677-37733914abda"]

PLATFORMS = {
    "windows": "Windows",
    "linux": "Linux",
    "macos": "MacOS",
    "azure-ad": "Windows",
    "office-365": "Windows",
    "containers": "Linux",
    "iaas:aws": ["Windows", "Linux", "MacOS"],
    "iaas:gcp": ["Windows", "Linux", "MacOS"],
    "iaas:azure": "Windows",
    "google-workspace": ["Windows", "Linux", "MacOS"],
}

EXECUTORS = {
    "powershell": "psh",
    "command_prompt": "cmd",
    "bash": "bash",
    "sh": "sh",
    "manual": "manual",
}


def flatten_chain(matrix):
    if matrix == []:
        return matrix
    if isinstance(matrix[0], list):
        return flatten_chain(matrix[0]) + flatten_chain(matrix[1:])
    return matrix[:1] + flatten_chain(matrix[1:])


class OpenBASAtomicRedTeam:
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
                    "default": "openbas_atomic_red_team",
                },
                "collector_log_level": {
                    "env": "COLLECTOR_LOG_LEVEL",
                    "file_path": ["collector", "log_level"],
                },
                "collector_period": {
                    "env": "COLLECTOR_PERIOD",
                    "file_path": ["collector", "period"],
                },
            },
        )
        self.helper = OpenBASCollectorHelper(
            self.config, "img/icon-atomic-red-team.png"
        )

    def _process_message(self) -> None:
        response = self.session.get(url=ATOMIC_RED_TEAM_INDEX)
        art_index = yaml.safe_load(response.text)
        for kill_chain_phase in art_index:
            self.helper.collector_logger.info(
                "Importing kill chain phase " + kill_chain_phase
            )
            for attack_pattern in art_index[kill_chain_phase]:
                self.helper.collector_logger.info(
                    "Importing attack pattern " + attack_pattern
                )
                for atomic_test in art_index[kill_chain_phase][attack_pattern][
                    "atomic_tests"
                ]:
                    arguments = []
                    if (
                        "input_arguments" in atomic_test
                        and atomic_test["input_arguments"] is not None
                    ):
                        for input_argument in atomic_test["input_arguments"]:
                            atomic_input_argument = atomic_test["input_arguments"][
                                input_argument
                            ]
                            argument = {
                                "type": "text",
                                "key": input_argument,
                                "default_value": atomic_input_argument["default"],
                            }
                            arguments.append(argument)
                    prerequisites = []
                    if (
                        "dependencies" in atomic_test
                        and atomic_test["dependencies"] is not None
                    ):
                        for dependency in atomic_test["dependencies"]:
                            prerequisite = {
                                "executor": EXECUTORS[
                                    atomic_test.get(
                                        "dependency_executor_name",
                                        atomic_test["executor"]["name"],
                                    )
                                ],
                                "description": dependency["description"],
                                "get_command": dependency["get_prereq_command"],
                                "check_command": dependency["prereq_command"],
                            }
                            prerequisites.append(prerequisite)
                    if (
                        "executor" in atomic_test
                        and "command" in atomic_test["executor"]
                        and atomic_test["executor"]["command"] is not None
                    ):
                        self.helper.collector_logger.info(
                            "Importing atomic test " + atomic_test["name"]
                        )
                        platforms = list(
                            dict.fromkeys(
                                flatten_chain(
                                    [
                                        PLATFORMS[platform]
                                        for platform in atomic_test[
                                            "supported_platforms"
                                        ]
                                    ]
                                )
                            )
                        )
                        platforms.sort()
                        payload = {
                            "payload_source": "COMMUNITY",
                            "payload_status": (
                                "VERIFIED"
                                if atomic_test["auto_generated_guid"]
                                in VERIFIED_PAYLOADS
                                else "UNVERIFIED"
                            ),
                            "payload_external_id": atomic_test["auto_generated_guid"],
                            "payload_type": "Command",
                            "payload_collector": self.helper.config.get("collector_id"),
                            "payload_name": atomic_test["name"],
                            "payload_description": atomic_test["description"],
                            "payload_platforms": platforms,
                            "payload_attack_patterns": [attack_pattern],
                            "payload_arguments": arguments,
                            "command_executor": EXECUTORS[
                                atomic_test["executor"]["name"]
                            ],
                            "command_content": atomic_test["executor"]["command"],
                            "payload_cleanup_command": atomic_test["executor"].get(
                                "cleanup_command", None
                            ),
                            "payload_cleanup_executor": EXECUTORS[
                                atomic_test["executor"]["name"]
                            ],
                            "payload_elevation_required": atomic_test["executor"].get(
                                "elevation_required", False
                            ),
                            "payload_prerequisites": prerequisites,
                        }
                        self.helper.api.payload.upsert(payload)

    # Start the main loop
    def start(self):
        period = self.config.get_conf(
            "collector_period", default=604800, is_number=True
        )  # 7 days
        self.helper.schedule(message_callback=self._process_message, delay=period)


if __name__ == "__main__":
    openBASAtomicRedTeam = OpenBASAtomicRedTeam()
    openBASAtomicRedTeam.start()
