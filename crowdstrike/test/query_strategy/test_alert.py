import unittest
from datetime import datetime
from test.fixtures import get_default_api_handler
from unittest.mock import patch

from crowdstrike.query_strategy.alert import Alert


class TestAlert(unittest.TestCase):
    @patch("falconpy.alerts.Alerts.query_alerts_v2")
    @patch("falconpy.alerts.Alerts.get_alerts_v2")
    def test_raw_data_from_api_is_correctly_formatted(
        self, mockGetAlerts, mockQueryAlerts
    ):
        mockQueryAlerts.return_value = {
            "status_code": 200,
            "body": {"resources": ["alert_id_1", "alert_id_2"]},
        }
        expected_alert_1_id = "alert_id_1"
        expected_alert_1_hostname = "endpoint"
        expected_alert_1_process_name = "some.exe"
        expected_alert_1_parent_process_name = "parent.exe"
        expected_alert_1_grandparent_process_name = "grandparent.exe"
        expected_alert_1_values = {
            "id": expected_alert_1_id,
            "hostname": expected_alert_1_hostname,
            "process_names": [
                expected_alert_1_process_name,
                expected_alert_1_parent_process_name,
                expected_alert_1_grandparent_process_name,
            ],
        }
        expected_alert_2_id = "alert_id_2"
        expected_alert_2_hostname = "endpoint"
        expected_alert_2_process_name = "other.exe"
        expected_alert_2_parent_process_name = "other_parent.exe"
        expected_alert_2_grandparent_process_name = "other_grandparent.exe"
        expected_alert_2_values = {
            "id": expected_alert_2_id,
            "hostname": expected_alert_2_hostname,
            "process_names": [
                expected_alert_2_process_name,
                expected_alert_2_parent_process_name,
                expected_alert_2_grandparent_process_name,
            ],
        }
        mockGetAlerts.return_value = {
            "status_code": 200,
            "body": {
                "resources": [
                    {
                        "id": expected_alert_1_id,
                        "device": {"hostname": expected_alert_1_hostname},
                        "filename": expected_alert_1_process_name,
                        "parent_details": {
                            "filename": expected_alert_1_parent_process_name
                        },
                        "grandparent_details": {
                            "filename": expected_alert_1_grandparent_process_name
                        },
                    },
                    {
                        "id": expected_alert_2_id,
                        "device": {"hostname": expected_alert_2_hostname},
                        "filename": expected_alert_2_process_name,
                        "parent_details": {
                            "filename": expected_alert_2_parent_process_name
                        },
                        "grandparent_details": {
                            "filename": expected_alert_2_grandparent_process_name
                        },
                    },
                ]
            },
        }

        strategy = Alert(api_handler=get_default_api_handler())
        actual_data = strategy.get_raw_data(start_time=datetime.now())

        self.assertEqual(actual_data[0].get_id(), expected_alert_1_values.get("id"))
        self.assertEqual(
            actual_data[0].get_process_image_names(),
            expected_alert_1_values.get("process_names"),
        )
        self.assertEqual(
            actual_data[0].get_hostname(), expected_alert_1_values.get("hostname")
        )
        self.assertEqual(actual_data[1].get_id(), expected_alert_2_values.get("id"))
        self.assertEqual(
            actual_data[1].get_process_image_names(),
            expected_alert_2_values.get("process_names"),
        )
        self.assertEqual(
            actual_data[1].get_hostname(), expected_alert_2_values.get("hostname")
        )


if __name__ == "__main__":
    unittest.main()
