import unittest
from datetime import datetime
from test.fixtures import get_default_api_handler
from unittest.mock import patch

from crowdstrike.query_strategy.alert import Alert


class TestAlert(unittest.TestCase):
    strategy = Alert(api_handler=get_default_api_handler())

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
        expected_alert_2_id = "alert_id_2"
        expected_alert_2_hostname = "endpoint"
        expected_alert_2_process_name = "other.exe"
        expected_alert_2_parent_process_name = "other_parent.exe"
        expected_alert_2_grandparent_process_name = "other_grandparent.exe"
        expected_values = {
            expected_alert_1_id: {
                "hostname": expected_alert_1_hostname,
                "process_names": [
                    expected_alert_1_process_name,
                    expected_alert_1_parent_process_name,
                    expected_alert_1_grandparent_process_name,
                ],
            },
            expected_alert_2_id: {
                "hostname": expected_alert_2_hostname,
                "process_names": [
                    expected_alert_2_process_name,
                    expected_alert_2_parent_process_name,
                    expected_alert_2_grandparent_process_name,
                ],
            },
        }

        # note that this is a truncated structure matching only a subset of keys present
        # in a returned json from the crowdstrike API.
        # Here are only the keys that are relevant to our collector
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

        actual_data = TestAlert.strategy.get_raw_data(start_time=datetime.now())

        self.assertEqual(len(actual_data), len(expected_values))

        for alert in actual_data:
            self.assertIsNotNone(expected_values.get(alert.get_id()))
            self.assertEqual(
                alert.get_hostname(), expected_values[alert.get_id()]["hostname"]
            )
            self.assertEqual(
                alert.get_process_image_names(),
                expected_values[alert.get_id()]["process_names"],
            )

    @patch("falconpy.alerts.Alerts.query_alerts_v2")
    def test_when_query_alerts_v2_error_return_no_items(self, mockQueryAlerts):
        mockQueryAlerts.return_value = {
            "status_code": 400,
            "body": {"errors": ["something wrong"], "resources": []},
        }

        actual_data = TestAlert.strategy.get_raw_data(start_time=datetime.now())

        self.assertEqual(len(actual_data), 0)


if __name__ == "__main__":
    unittest.main()
