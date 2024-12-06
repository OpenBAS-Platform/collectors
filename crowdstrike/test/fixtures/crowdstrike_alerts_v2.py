QUERY_ALERTS_V2_SUCCESS_RESPONSE = {
    "status_code": 200,
    "body": {"errors": [], "resources": ["alert_id_1", "alert_id_2"]},
}
QUERY_ALERTS_V2_FAILURE_RESPONSE = {
    "status_code": 400,
    "body": {"errors": ["something went wrong?"], "resources": []},
}


def make_test_alert_data():
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
    get_alerts_v2_success_response = {
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
                    "pattern_disposition": 0
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
                    "pattern_disposition": 0
                },
            ]
        },
    }
    get_alerts_v2_success_response_with_malformed_data = {
        "status_code": 200,
        "body": {
            "resources": [
                {},
            ]
        },
    }
    return (
        expected_values,
        get_alerts_v2_success_response,
        get_alerts_v2_success_response_with_malformed_data,
    )


(
    ALERT_DATA,
    GET_ALERTS_V2_SUCCESS_RESPONSE,
    GET_ALERTS_V2_SUCCESS_RESPONSE_WITH_MALFORMED_DATA,
) = make_test_alert_data()
GET_ALERTS_V2_SUCCESS_RESPONSE_NO_ITEMS = {
    "status_code": 200,
    "body": {"errors": [], "resources": []},
}
GET_ALERTS_V2_FAILURE_RESPONSE = {
    "status_code": 400,
    "body": {"errors": ["something wrong here"], "resources": []},
}
