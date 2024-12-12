import unittest
from test.fixtures.defaults import TestStrategy, get_default_collector
from unittest.mock import patch


class TestOpenBASCrowdstrike(unittest.TestCase):
    @patch("pyobas.apis.InjectExpectationManager.update")
    def test_when_alert_matches_update_prevention_expectation(
        self, mock_expectation_update
    ):
        expected_expectation_id = "expectation_id"
        expectations = [
            {
                "inject_expectation_type": "PREVENTION",
                "inject_expectation_id": expected_expectation_id,
                "inject_expectation_signatures": [
                    {"type": "parent_process_name", "value": "grandparent.exe"},
                ],
            }
        ]

        signature_data = {
            "parent_process_name": {
                "type": "fuzzy",
                "data": ["grandparent.exe", "some_process.exe"],
                "score": 95,
            },
        }

        strategy = TestStrategy(
            raw_data_callback=lambda: None,
            signature_data_callback=lambda: signature_data,
            is_prevented_callback=lambda: True,
            get_alert_id_callback=lambda: expected_expectation_id,
        )

        collector = get_default_collector(strategy)

        collector._match_expectations(["alert"], expectations)

        mock_expectation_update.assert_called_once_with(
            expected_expectation_id,
            {
                "collector_id": collector.config.get_conf("collector_id"),
                "result": "Prevented",
                "is_success": True,
                "metadata": {"alertId": expected_expectation_id},
            },
        )

    @patch("pyobas.apis.InjectExpectationManager.update")
    def test_when_alert_matches_but_not_prevented_update_prevention_expectation(
        self, mock_expectation_update
    ):
        expected_expectation_id = "expectation_id"
        expectations = [
            {
                "inject_expectation_type": "PREVENTION",
                "inject_expectation_id": expected_expectation_id,
                "inject_expectation_signatures": [
                    {"type": "parent_process_name", "value": "grandparent.exe"},
                ],
            }
        ]

        signature_data = {
            "parent_process_name": {
                "type": "fuzzy",
                "data": ["grandparent.exe", "some_process.exe"],
                "score": 95,
            },
        }

        strategy = TestStrategy(
            raw_data_callback=lambda: None,
            signature_data_callback=lambda: signature_data,
            is_prevented_callback=lambda: False,
            get_alert_id_callback=lambda: expected_expectation_id,
        )

        collector = get_default_collector(strategy)

        collector._match_expectations(["alert"], expectations)

        mock_expectation_update.assert_called_once_with(
            expected_expectation_id,
            {
                "collector_id": collector.config.get_conf("collector_id"),
                "result": "Not Prevented",
                "is_success": False,
                "metadata": {"alertId": expected_expectation_id},
            },
        )

    @patch("pyobas.apis.InjectExpectationManager.update")
    def test_when_alert_matches_update_detection_expectation(
        self, mock_expectation_update
    ):
        expected_expectation_id = "expectation_id"
        expectations = [
            {
                "inject_expectation_type": "DETECTION",
                "inject_expectation_id": expected_expectation_id,
                "inject_expectation_signatures": [
                    {"type": "parent_process_name", "value": "grandparent.exe"},
                ],
            }
        ]

        signature_data = {
            "parent_process_name": {
                "type": "fuzzy",
                "data": ["grandparent.exe", "some_process.exe"],
                "score": 95,
            },
        }

        strategy = TestStrategy(
            raw_data_callback=lambda: None,
            signature_data_callback=lambda: signature_data,
            is_prevented_callback=lambda: True,
            get_alert_id_callback=lambda: expected_expectation_id,
        )

        collector = get_default_collector(strategy)

        collector._match_expectations(["alert"], expectations)

        mock_expectation_update.assert_called_once_with(
            expected_expectation_id,
            {
                "collector_id": collector.config.get_conf("collector_id"),
                "result": "Detected",
                "is_success": True,
                "metadata": {"alertId": expected_expectation_id},
            },
        )

    @patch("pyobas.apis.InjectExpectationManager.update")
    def test_when_expectation_has_expected_hostname_signature_ignore_it(
        self, mock_expectation_update
    ):
        expected_expectation_id = "expectation_id"
        expectations = [
            {
                "inject_expectation_type": "DETECTION",
                "inject_expectation_id": expected_expectation_id,
                "inject_expectation_signatures": [
                    {"type": "parent_process_name", "value": "grandparent.exe"},
                    {"type": "hostname", "value": "some_host"},
                ],
            }
        ]

        signature_data = {
            "parent_process_name": {
                "type": "fuzzy",
                "data": ["grandparent.exe", "some_process.exe"],
                "score": 95,
            },
        }

        strategy = TestStrategy(
            raw_data_callback=lambda: None,
            signature_data_callback=lambda: signature_data,
            is_prevented_callback=lambda: True,
            get_alert_id_callback=lambda: expected_expectation_id,
        )

        collector = get_default_collector(strategy)

        collector._match_expectations(["alert"], expectations)

        mock_expectation_update.assert_called_once_with(
            expected_expectation_id,
            {
                "collector_id": collector.config.get_conf("collector_id"),
                "result": "Detected",
                "is_success": True,
                "metadata": {"alertId": expected_expectation_id},
            },
        )

    @patch("pyobas.apis.InjectExpectationManager.update")
    def test_when_alert_fails_to_match_dont_update_prevention_expectation(
        self, mock_expectation_update
    ):
        expected_expectation_id = "expectation_id"
        expectations = [
            {
                "inject_expectation_type": "PREVENTION",
                "inject_expectation_id": expected_expectation_id,
                "inject_expectation_signatures": [
                    {"type": "parent_process_name", "value": "unknown_process.exe"},
                ],
            }
        ]

        signature_data = {
            "parent_process_name": {
                "type": "fuzzy",
                "data": ["grandparent.exe", "some_process.exe"],
                "score": 95,
            },
        }

        strategy = TestStrategy(
            raw_data_callback=lambda: None,
            signature_data_callback=lambda: signature_data,
            is_prevented_callback=lambda: False,
            get_alert_id_callback=lambda: expected_expectation_id,
        )

        collector = get_default_collector(strategy)

        collector._match_expectations(["alert"], expectations)

        mock_expectation_update.assert_not_called()

    @patch("pyobas.apis.InjectExpectationManager.update")
    def test_when_signatures_match_when_unknown_expectation_type_skip_updating_expectation(
        self, mock_expectation_update
    ):
        expected_expectation_id = "expectation_id"
        expectations = [
            {
                "inject_expectation_type": "SOME UNKNOWN EXPECTATION TYPE",
                "inject_expectation_id": expected_expectation_id,
                "inject_expectation_signatures": [
                    {"type": "parent_process_name", "value": "grandparent.exe"},
                ],
            }
        ]

        signature_data = {
            "parent_process_name": {
                "type": "fuzzy",
                "data": ["grandparent.exe", "some_process.exe"],
                "score": 95,
            },
        }

        strategy = TestStrategy(
            raw_data_callback=lambda: None,
            signature_data_callback=lambda: signature_data,
            is_prevented_callback=lambda: True,
            get_alert_id_callback=lambda: expected_expectation_id,
        )

        collector = get_default_collector(strategy)

        collector._match_expectations(["alert"], expectations)

        mock_expectation_update.assert_not_called()


if __name__ == "__main__":
    unittest.main()
