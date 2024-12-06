import unittest

from crowdstrike.pattern_disposition import (
    is_prevented,
    PREVENT_BLOCK_PROCESS,
    PREVENT_KILL_PARENT,
    PREVENT_SUSPEND_PARENT,
    PREVENT_SUSPEND_PROCESS,
    PREVENT_KILL_PROCESS,
    PREVENT_HANDLE_OPERATION_DOWNGRADED,
    PREVENT_FS_OPERATION_BLOCKED,
    PREVENT_REG_OPERATION_BLOCKED,
    PREVENT_QUARANTINE_FILE,
    PREVENT_OPERATION_BLOCKED,
    MODIFY_CRITICAL_PROCESS_DISABLED,
    MODIFY_POLICY_DISABLED,
    MODIFY_BLOCKING_UNSUPPORTED_OR_DISABLED,
    MODIFY_KILL_ACTION_FAILED,
    MODIFY_RESPONSE_ACTION_FAILED,
    MODIFY_RESPONSE_ACTION_ALREADY_APPLIED,
    MODIFY_BOOTUP_SAFEGUARD_ENABLED, ALL_PREVENT, ALL_MODIFY,
)


class TestAlert(unittest.TestCase):
    def test_when_pattern_disposition_is_process_killed_when_not_disabled_return_true(
        self,
    ):
        pattern_disposition = PREVENT_KILL_PROCESS

        result = is_prevented(pattern_disposition)

        self.assertTrue(result)

    def test_when_pattern_disposition_is_process_killed_when_failed_return_false(
        self,
    ):
        pattern_disposition = (
            PREVENT_KILL_PROCESS | MODIFY_KILL_ACTION_FAILED
        )

        result = is_prevented(pattern_disposition)

        self.assertFalse(result)

    def test_when_pattern_disposition_is_all_prevents_when_none_are_disabled_return_true(
        self,
    ):
        pattern_disposition = (
            ALL_PREVENT
        )

        result = is_prevented(pattern_disposition)

        self.assertTrue(result)

    def test_when_pattern_disposition_is_all_prevents_when_some_are_disabled_return_false(
        self,
    ):
        pattern_disposition = (
            ALL_PREVENT | MODIFY_KILL_ACTION_FAILED | MODIFY_POLICY_DISABLED
        )

        result = is_prevented(pattern_disposition)

        self.assertFalse(result)

    def test_when_pattern_disposition_is_all_prevents_when_all_are_disabled_return_false(
        self,
    ):
        pattern_disposition = (
            ALL_PREVENT | ALL_MODIFY
        )

        result = is_prevented(pattern_disposition)

        self.assertFalse(result)


if __name__ == "__main__":
    unittest.main()
