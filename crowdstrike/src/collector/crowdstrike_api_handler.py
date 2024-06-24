######################
# CROWDSTRIKE API HANDLER #
######################

from falconpy import IOC as CrowdstrikeIOC
from .utils import Utils

class CrowdstrikeApiHandler:
    def __init__(self, helper, client_id, client_secret, base_url):
        self.helper = helper
        self.client_id = client_id
        self.client_secret = client_secret
        self.base_url = base_url

        self._auth()

    def _auth(self):
        self.cs = CrowdstrikeIOC(
            client_id=self.client_id,
            client_secret=self.client_secret,
            base_url=self.base_url,
        )

    def extract_iocs(self):
        """
        Retrieve all IOCs from CrowdStrike and process them into a readable
        format.
        """
        response = self.cs.indicator_combined_v1()
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

