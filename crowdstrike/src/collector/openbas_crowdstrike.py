from pyobas.helpers import (
    OpenBASCollectorHelper,
    OpenBASConfigHelper,
)
from .crowdstrike_api_handler import CrowdstrikeApiHandler


class OpenBASCrowdStrike:
    def __init__(self):
        self.config = OpenBASConfigHelper(
          __file__,
          {
            # API information
            "openbas_url": {"env": "OPENBAS_URL", "file_path": ["openbas", "url"]},
            "openbas_token": {"env": "OPENBAS_TOKEN", "file_path": ["openbas", "token"]},
            # Config information
            "collector_id": {"env": "COLLECTOR_ID", "file_path": ["collector", "id"]},
            "collector_name": {"env": "COLLECTOR_NAME", "file_path": ["collector", "name"]},
            "collector_type": {"env": "COLLECTOR_TYPE", "file_path": ["collector", "type"], "default": "openbas_crowdstream"},
            "collector_period": {"env": "COLLECTOR_PERIOD", "file_path": ["collector", "period"]},
            "collector_log_level": {"env": "COLLECTOR_LOG_LEVEL", "file_path": ["collector", "log_level"]},
            # CrowdStrike
            "crowdstrike_client_id": {"env": "CROWDSTRIKE_CLIENT_ID", "file_path": ["crowdstrike", "client_id"], "default": "CHANGEME"},
            "crowdstrike_client_secret": {"env": "CROWDSTRIKE_CLIENT_SECRET", "file_path": ["crowdstrike", "client_secret"], "default": "CHANGEME"},
            "crowdstrike_api_base_url": {"env": "CROWDSTRIKE_API_BASE_URL", "file_path": ["crowdstrike", "api_base_url"], "default": "https://api.crowdstrike.com"},
          },
        )
        self.helper = OpenBASCollectorHelper(self.config, open("img/icon-crowdstrike.png", "rb"))

        # Initialize CrowdStrike API
        self.crowdstrike_api_handler = CrowdstrikeApiHandler(
          self.helper,
          self.config.get_conf("crowdstrike_client_id"),
          self.config.get_conf("crowdstrike_client_secret"),
          self.config.get_conf("crowdstrike_api_base_url"),
        )

    def _match_expectations(self):
        """
        Retrieve and process the expectations from openBAS and match them with
        the retrieved IOCs.
        """
        try:
            iocs = self.crowdstrike_api_handler.extract_iocs()
            print(iocs)
            # Process alerts and incidents if needed
        except Exception as e:
            print(f"Error matching expectations: {e}")

    def _process_messages(self):
        self._match_expectations()

    def start(self):
        period = self.config.get_conf("collector_period", True, 60)
        self.helper.schedule(self._process_messages, period)

