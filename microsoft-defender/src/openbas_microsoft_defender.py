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

        # Graph client authentication
        scopes = ["https://graph.microsoft.com/.default"]

        # Values from app registration
        # azure.identity.aio
        credential = ClientSecretCredential(
            tenant_id=self.config.get_conf("microsoft_defender_tenant_id"),
            client_id=self.config.get_conf("microsoft_defender_client_id"),
            client_secret=self.config.get_conf("microsoft_defender_client_secret"),
        )

        self.graph_client = GraphServiceClient(credential, scopes)  # type: ignore

    async def _process_alerts(self):
        self.helper.collector_logger.info("Gathering expectations for executed injects")
        expectations = self.helper.api.inject_expectation.expectations_for_source(
            self.config.get_conf("collector_id")
        )
        limit_date = datetime.now().astimezone(pytz.UTC) - relativedelta(minutes=45)
        query_params = (
            Alerts_v2RequestBuilder.Alerts_v2RequestBuilderGetQueryParameters(
                orderby=["createdDateTime DESC"], top=100
            )
        )
        request_configuration = RequestConfiguration(query_parameters=query_params)
        alerts = await self.graph_client.security.alerts_v2.get(
            request_configuration=request_configuration
        )
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
            for i in range(len(alerts.value)):
                alert = alerts.value[i]

    def _process_message(self) -> None:
        asyncio.run(self._process_alerts())

    # Start the main loop
    def start(self):
        period = self.config.get_conf("collector_period", default=60, is_number=True)
        self.helper.schedule(message_callback=self._process_message, delay=period)


if __name__ == "__main__":
    openBASMicrosoftDefender = OpenBASMicrosoftDefender()
    openBASMicrosoftDefender.start()
