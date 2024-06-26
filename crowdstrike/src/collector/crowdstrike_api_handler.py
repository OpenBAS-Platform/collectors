from falconpy import IOC as CsIOC
from falconpy import Alerts as CsAlerts
from falconpy import Incidents as CsIncidents

from .utils import Utils


class CrowdstrikeApiHandler:
    def __init__(self, helper, client_id, client_secret, base_url):
        self.helper = helper
        self.client_id = client_id
        self.client_secret = client_secret
        self.base_url = base_url

        self._auth()

    def _init_service(self, service_class):
        return service_class(
            client_id=self.client_id,
            client_secret=self.client_secret,
            base_url=self.base_url
        )

    def _auth(self):
        self.ioc = self._init_service(CsIOC)
        self.alerts = self._init_service(CsAlerts)
        self.incidents = self._init_service(CsIncidents)

    def extract_iocs(self):
        response = self.ioc.indicator_combined_v1()
        if response["status_code"] != 200:
            raise Exception(f"Failed to retrieve IOCs: {response['errors']}")

        iocs = response["body"]["resources"]
        extracted_iocs = []

        for ioc in iocs:
            if ioc["type"] in ["ipv4", "ipv6"]:
                extracted_iocs.append(Utils.format_ioc("IP Address", ioc))
            elif ioc["type"] == "domain":
                extracted_iocs.append(Utils.format_ioc("Domain Name", ioc))
            elif ioc["type"] in ["sha256", "md5"]:
                extracted_iocs.append(Utils.format_ioc("File Hash", ioc))
            elif ioc["type"] == "all_subdomains":
                extracted_iocs.append(Utils.format_ioc("Subdomains", ioc))

        return extracted_iocs
