import unittest
from unittest.mock import patch

from test.fixtures.defaults import TestStrategy, get_default_collector


class TestOpenBASCrowdstrike(unittest.TestCase):
    @patch("pyobas.apis.EndpointManager.get")
    def test_when_no_expectations_nothing_happens(self, mock_endpoint_get):
        expectations = []
        alerts = []

        strategy = TestStrategy(
            raw_data_callback=lambda: alerts,
            signature_data_callback=lambda: [],
            is_prevented_callback=lambda: True
        )
        collector = get_default_collector(strategy)

        collector._match_expectations(alerts, expectations)

        mock_endpoint_get.assert_not_called()

    @patch("pyobas.apis.EndpointManager.get")
    @patch("pyobas.apis.InjectExpectationManager.update")
    def test_when_alert_matches_expectation(self, mock_expectation_update, mock_endpoint_get):
        mock_endpoint_get.return_value = { "endpoint_hostname": "some_host" }
        expected_expectation_id = "expectation_id"
        expectations = [
            {
                "inject_expectation_type": "PREVENTION",
                "inject_expectation_id": expected_expectation_id,
                "inject_expectation_asset": "some_host",
                "inject_expectation_signatures": [
                    {
                        "type": "parent_process_name",
                        "value": "grandparent.exe"
                    },
                    {
                        "type": "hostname",
                        "value": "some_host"
                    }
                ]
            }
        ]

        signature_data = {
            "parent_process_name":
            {
                "type": "fuzzy",
                "data": ["grandparent.exe", "some_process.exe"],
                "score": 95
            },
            "hostname":
            {
                "type": "simple",
                "data": ["some_host"]
            }
        }

        strategy = TestStrategy(
            raw_data_callback=lambda: None,
            signature_data_callback=lambda: signature_data,
            is_prevented_callback=lambda: True
        )

        collector = get_default_collector(strategy)

        collector._match_expectations(["alert"], expectations)

        mock_endpoint_get.assert_called_once()
        mock_expectation_update.assert_called_once_with(expected_expectation_id, {
                            "collector_id": "collector_id",
                            "result": "Prevented",
                            "is_success": True,
                            "metadata": {"alertId": "some_id"},
                        })


if __name__ == '__main__':
    unittest.main()
