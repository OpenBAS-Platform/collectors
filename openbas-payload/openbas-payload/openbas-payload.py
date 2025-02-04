import json
from itertools import islice

import requests
from daemons import CollectorDaemon
from pyobas.configuration import Configuration

# Can have a delay due to cache on github side
OPENBAS_PAYLOAD_INDEX = "https://raw.githubusercontent.com/OpenBAS-Platform/payloads/refs/heads/issue/1991/indexes/full-payloads.json"


class OpenBASPayload:
    def __init__(self, collector):
        self.session = requests.Session()
        self.logger = collector.logger
        self.api = collector.api
        self.collector_id = collector.get_id()

    BATCH_SIZE = 50

    def batch(self, iterable):
        iterator = iter(iterable)
        while batch := list(islice(iterator, self.BATCH_SIZE)):
            yield batch

    def process_message(self) -> None:
        response = self.session.get(url=OPENBAS_PAYLOAD_INDEX)
        data = json.loads(response.text)

        for ttp in data:
            self._process_ttp(ttp)

    def _process_ttp(self, data) -> None:
        payloads = []
        for atomic_testing in data["atomic-testings"]:
            payloads.append(
                {
                    **atomic_testing,
                    "payload_version": int(atomic_testing.get("payload_version")),
                    "payload_attack_patterns": [data.get("ID")],
                    "payload_source": "FILIGRAN",
                    "payload_status": "VERIFIED",
                    "payload_collector": self.collector_id,
                }
            )
            self.logger.info(
                "Importing atomic test " + atomic_testing.get("payload_name")
            )

        for batch_payloads in self.batch(payloads):
            self.logger.info(f"Importing {len(batch_payloads)} payloads")
            self.api.payload.upsert_bulk(batch_payloads)


if __name__ == "__main__":
    config = Configuration(
        config_hints={
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
                "default": "openbas_payload",
            },
            "collector_log_level": {
                "env": "COLLECTOR_LOG_LEVEL",
                "file_path": ["collector", "log_level"],
            },
            "collector_period": {
                "env": "COLLECTOR_PERIOD",
                "file_path": ["collector", "period"],
                "default": 604800,
            },
            "collector_icon_filepath": {"data": "img/icon-obas-payload.png"},
        }
    )
    openBASPayloadCollector = CollectorDaemon(config)
    openBASPayload = OpenBASPayload(openBASPayloadCollector)
    openBASPayloadCollector.set_callback(openBASPayload.process_message)
    openBASPayloadCollector.start()
