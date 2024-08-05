from falconpy import IOC as CsIOC
from falconpy import Alerts as CsAlerts
from falconpy import Detects as CsDetects

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
            base_url=self.base_url,
        )

    def _auth(self):
        self.ioc = self._init_service(CsIOC)
        self.alerts = self._init_service(CsAlerts)
        self.detections = self._init_service(CsDetects)

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

    def extract_alerts(self, start_time):
        try:
            parameters = {
                "filter": f"timestamp:>'{start_time.isoformat()}'",
            }
            response = self.alerts.query_alerts(parameters=parameters)

            alerts = []

            if response["status_code"] == 200:
                alert_ids = response["body"]["resources"]

                # Get detailed information for each alert
                for alert_id in alert_ids:
                    detail_response = self.alerts.get_details(ids=[alert_id])
                    if detail_response["status_code"] == 200:
                        alerts.append(detail_response["body"]["resources"][0])
                    else:
                        print(
                            f"Failed to get details for alert ID {alert_id}: {detail_response}"
                        )
            else:
                print("Failed to query alerts:", response)
            return alerts
        except Exception as e:
            print(f"Error: {e}")

    def extract_detects(self, start_time):
        try:
            parameters = {
                "filter": f"created_timestamp:>'{start_time.isoformat()}'",
                "limit": 10,
            }

            # Make the API call to retrieve detections
            response = self.detections.query_detects(parameters=parameters)
            detections = []

            if response["status_code"] == 200:
                detection_ids = response["body"]["resources"]
                for detection_id in detection_ids:
                    detection_details = self.detections.get_details(ids=[detection_id])
                    if detection_details["status_code"] == 200:
                        detections.append(detection_details["body"]["resources"][0])
                    else:
                        print(f"Failed to get details for detection ID: {detection_id}")
            else:
                print("Failed to retrieve detections:", response)

            return detections
        except Exception as e:
            print("Error:", e)
