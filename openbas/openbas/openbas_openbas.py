import requests
from pyobas.helpers import OpenBASCollectorHelper, OpenBASConfigHelper


class OpenBASOpenBAS:
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
                    "default": "OpenBAS Datasets",
                },
                "collector_type": {
                    "env": "COLLECTOR_TYPE",
                    "file_path": ["collector", "type"],
                    "default": "openbas_openbas",
                },
                "collector_log_level": {
                    "env": "COLLECTOR_LOG_LEVEL",
                    "file_path": ["collector", "log_level"],
                    "default": "error",
                },
                "collector_period": {
                    "env": "COLLECTOR_PERIOD",
                    "file_path": ["collector", "period"],
                    "default": 604800,
                },
                # OpenBAS Datasets
                "openbas_manifest_url": {
                    "env": "OPENBAS_MANIFEST_URL",
                    "file_path": ["openbas", "manifest_url"],
                },
            },
        )
        self.helper = OpenBASCollectorHelper(
            self.config, "openbas/img/icon-openbas.png"
        )

    def _process_message(self) -> None:
        manifest_url = self.config.get_conf(
            "openbas_manifest_url",
            default="https://raw.githubusercontent.com/OpenBAS-Platform/payloads/refs/heads/main/manifest.json",
        )
        response = self.session.get(url=manifest_url)
        payloads = response.json()
        payload_external_ids = []

        for payload in payloads:
            self.helper.collector_logger.info(
                "Importing payload " + payload["payload_name"]
            )
            payload["payload_collector"] = self.helper.config.get("collector_id")

            self.helper.api.payload.upsert(payload)
            payload_external_ids.append(payload["payload_external_id"])
        self.helper.api.payload.deprecate(
            {
                "collector_id": self.helper.config.get("collector_id"),
                "payload_external_ids": payload_external_ids,
            }
        )

    # Start the main loop
    def start(self):
        period = self.config.get_conf(
            "collector_period", default=604800, is_number=True
        )  # 7 days
        self.helper.schedule(message_callback=self._process_message, delay=period)


if __name__ == "__main__":
    openBASAtomicRedTeam = OpenBASOpenBAS()
    openBASAtomicRedTeam.start()
