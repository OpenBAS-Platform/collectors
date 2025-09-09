"""Generic Expectation Manager."""

import logging
import time
from datetime import datetime, timedelta
from typing import Any

from pyobas.apis.inject_expectation.model import (  # type: ignore[import-untyped]
    DetectionExpectation,
    PreventionExpectation,
)
from pyobas.client import OpenBAS  # type: ignore[import-untyped]
from pyobas.helpers import OpenBASDetectionHelper  # type: ignore[import-untyped]
from pyobas.signatures.types import SignatureTypes  # type: ignore[import-untyped]

from .exception import (
    APIError,
    BulkUpdateError,
    ExpectationProcessingError,
    ExpectationUpdateError,
)
from .expectation_handler import GenericExpectationHandler
from .models import ExpectationResult, ProcessingSummary
from .trace_manager import TraceManager
from .trace_service_provider import TraceServiceProvider

LOG_PREFIX = "[CollectorExpectationManager]"

# Constants
FETCH_TIMEOUT_MINUTES = 5
SLEEP_INTERVAL_SECONDS = 30
PROGRESS_LOG_INTERVAL = 10


class GenericExpectationManager:
    """Generic expectation manager that works with any service provider.

    This manager is completely agnostic to the specific use case and
    delegates all processing logic to the injected service providers.
    """

    def __init__(
        self,
        oaev_api: OpenBAS,
        collector_id: str,
        expectation_handler: GenericExpectationHandler,
        trace_service: TraceServiceProvider | None = None,
    ) -> None:
        """Initialize generic expectation manager.

        Args:
            oaev_api: OpenBAS API client.
            collector_id: ID of the collector.
            expectation_handler: Handler for processing expectations.
            trace_service: Optional service for creating traces.

        Raises:
            ValueError: If required parameters are None or empty.

        """
        if not oaev_api:
            raise ValueError("oaev_api cannot be None")
        if not collector_id:
            raise ValueError("collector_id cannot be empty")
        if not expectation_handler:
            raise ValueError("expectation_handler cannot be None")

        self.logger = logging.getLogger(__name__)
        self.oaev_api = oaev_api
        self.collector_id = collector_id
        self.expectation_handler = expectation_handler
        self.trace_manager = TraceManager(
            oaev_api=oaev_api,
            collector_id=collector_id,
            trace_service=trace_service,
        )

        self.logger.info(
            f"{LOG_PREFIX} Expectation manager initialized for collector: {collector_id}"
        )

    def process_expectations(
        self, detection_helper: OpenBASDetectionHelper
    ) -> ProcessingSummary:
        """Process all expectations using the injected handler.

        Fetches expectations from OpenBAS, processes them through the handler,
        updates expectations in OpenBAS, and creates traces.

        Args:
            detection_helper: OpenBAS detection helper.

        Returns:
            ProcessingSummary containing processing results.

        Raises:
            ExpectationProcessingError: If processing fails.

        """
        try:
            self.logger.info(f"{LOG_PREFIX} Starting expectation processing cycle")

            self.logger.debug(f"{LOG_PREFIX} Fetching expectations from OpenBAS...")
            expectations = self._fetch_expectations_with_timeout()

            if not expectations:
                self.logger.warning(f"{LOG_PREFIX} No expectations found to process")
                return ProcessingSummary(processed=0, valid=0, invalid=0, skipped=0)

            supported_expectations = [
                exp
                for exp in expectations
                if isinstance(exp, (DetectionExpectation, PreventionExpectation))
            ]

            total_expectations = len(expectations)
            supported_count = len(supported_expectations)
            skipped_count = total_expectations - supported_count

            self.logger.info(
                f"{LOG_PREFIX} Found {total_expectations} total expectations: "
                f"{supported_count} supported, {skipped_count} skipped"
            )

            if skipped_count > 0:
                self.logger.debug(
                    f"{LOG_PREFIX} Skipped {skipped_count} unsupported expectation types"
                )

            self.logger.debug(
                f"{LOG_PREFIX} Processing expectations through handler..."
            )
            results = self.expectation_handler.handle_batch_expectations(
                supported_expectations, detection_helper
            )

            self.logger.debug(f"{LOG_PREFIX} Updating expectations in OpenBAS...")
            self._bulk_update_expectations(results)

            self.logger.debug(f"{LOG_PREFIX} Creating and submitting traces...")
            self.trace_manager.create_and_submit_traces(results)

            valid_count = sum(1 for r in results if r.is_valid)
            invalid_count = len(results) - valid_count

            summary = ProcessingSummary(
                processed=len(results),
                valid=valid_count,
                invalid=invalid_count,
                skipped=skipped_count,
            )

            self.logger.info(
                f"{LOG_PREFIX} Expectation processing: processed {total_expectations} items -> {len(results)} results"
            )

            self.logger.info(
                f"{LOG_PREFIX} Processing cycle completed: {valid_count} valid, "
                f"{invalid_count} invalid, {skipped_count} skipped"
            )

            return summary

        except (BulkUpdateError, APIError) as e:
            self.logger.error(f"{LOG_PREFIX} API operation failed: {e}")
            raise ExpectationProcessingError(f"API error during processing: {e}") from e
        except Exception as e:
            self.logger.error(f"{LOG_PREFIX} Unexpected error during processing: {e}")
            raise ExpectationProcessingError(
                f"Unexpected error processing expectations: {e}"
            ) from e

    def _bulk_update_expectations(self, results: list[ExpectationResult]) -> None:
        """Bulk update expectations in OpenBAS.

        Prepares bulk data from results and attempts to update expectations
        using the OpenBAS bulk update API.

        Args:
            results: List of ExpectationResult objects to update.

        Raises:
            BulkUpdateError: If bulk update fails.

        """
        if not results:
            self.logger.debug(
                f"{LOG_PREFIX} No results to update, skipping bulk update"
            )
            return

        try:
            self.logger.debug(
                f"{LOG_PREFIX} Preparing bulk data for {len(results)} results..."
            )
            bulk_data = self._prepare_bulk_data(results)

            if bulk_data:
                self.logger.debug(
                    f"{LOG_PREFIX} Attempting bulk update of {len(bulk_data)} expectations..."
                )
                self._attempt_bulk_update(bulk_data)
            else:
                self.logger.debug(
                    f"{LOG_PREFIX} No valid bulk data prepared, skipping update"
                )

        except Exception as e:
            self.logger.error(f"{LOG_PREFIX} Bulk update failed: {e}")
            raise BulkUpdateError(f"Error in bulk update: {e}") from e

    def _prepare_bulk_data(
        self, results: list[ExpectationResult]
    ) -> dict[str, dict[str, Any]]:
        """Prepare bulk data from results.

        Transforms ExpectationResult objects into dictionary format
        required by the OpenBAS bulk update API.

        Args:
            results: List of ExpectationResult objects.

        Returns:
            Dictionary mapping expectation IDs to update data.

        """
        bulk_data = {}
        skipped_count = 0

        for result in results:
            try:
                expectation_id = result.expectation_id
                if not expectation_id:
                    skipped_count += 1
                    self.logger.debug(
                        f"{LOG_PREFIX} Skipping result without expectation_id"
                    )
                    continue

                is_valid = result.is_valid
                expectation = result.expectation
                if expectation:
                    result_text = self._get_result_text(expectation, is_valid)
                    bulk_data[expectation_id] = {
                        "collector_id": self.collector_id,
                        "result": result_text,
                        "is_success": is_valid,
                    }
                    self.logger.debug(
                        f"{LOG_PREFIX} Prepared update for expectation {expectation_id}: "
                        f"result='{result_text}', success={is_valid}"
                    )
                else:
                    skipped_count += 1
                    self.logger.debug(
                        f"{LOG_PREFIX} Skipping result {expectation_id} without expectation object"
                    )
            except Exception as e:
                skipped_count += 1
                self.logger.warning(f"{LOG_PREFIX} Error processing result: {e}")

        if skipped_count > 0:
            self.logger.debug(
                f"{LOG_PREFIX} Skipped {skipped_count} results during bulk data preparation"
            )
        return bulk_data

    def _get_result_text(
        self, expectation: DetectionExpectation | PreventionExpectation, is_valid: bool
    ) -> str:
        """Get result text based on expectation type and validity.

        Args:
            expectation: The expectation object (Detection or Prevention).
            is_valid: Whether the expectation was successfully validated.

        Returns:
            Human-readable result text for the expectation.

        """
        try:
            base_text = (
                "Detected"
                if isinstance(expectation, DetectionExpectation)
                else "Prevented"
            )
            result_text = base_text if is_valid else f"Not {base_text}"

            self.logger.debug(
                f"{LOG_PREFIX} Generated result text: '{result_text}' for {type(expectation).__name__}"
            )
            return result_text
        except Exception as e:
            self.logger.warning(f"{LOG_PREFIX} Error generating result text: {e}")
            return "Unknown"

    def _attempt_bulk_update(self, bulk_data: dict[str, dict[str, Any]]) -> None:
        """Attempt bulk update with fallback to individual updates.

        Tries to use the bulk update API first, then falls back to individual
        updates if the bulk operation fails.

        Args:
            bulk_data: Dictionary of expectation updates to apply.

        Raises:
            BulkUpdateError: If both bulk and individual updates fail.

        """
        try:
            self.logger.debug(f"{LOG_PREFIX} Attempting bulk update via OpenBAS API...")
            self.oaev_api.inject_expectation.bulk_update(
                inject_expectation_input_by_id=bulk_data
            )
            self.logger.info(
                f"{LOG_PREFIX} Successfully bulk updated {len(bulk_data)} expectations"
            )

        except Exception as bulk_error:
            self.logger.warning(
                f"{LOG_PREFIX} Bulk update failed, falling back to individual updates: {bulk_error}"
            )
            try:
                self._fallback_individual_updates(bulk_data)
            except Exception as fallback_error:
                raise BulkUpdateError(
                    f"Both bulk and individual updates failed: {fallback_error}"
                ) from fallback_error

    def _fallback_individual_updates(
        self, bulk_data: dict[str, dict[str, Any]]
    ) -> None:
        """Fallback to individual expectation updates.

        Updates expectations one by one when bulk update fails.

        Args:
            bulk_data: Dictionary of expectation updates to apply.

        """
        self.logger.info(
            f"{LOG_PREFIX} Attempting individual updates for {len(bulk_data)} expectations"
        )
        success_count = 0
        error_count = 0

        for expectation_id, update_data in bulk_data.items():
            try:
                self._update_expectation(expectation_id, update_data)
                success_count += 1
            except (APIError, ExpectationUpdateError) as e:
                error_count += 1
                self.logger.error(
                    f"{LOG_PREFIX} Failed to update expectation {expectation_id}: {e}"
                )
            except Exception as e:
                error_count += 1
                self.logger.error(
                    f"{LOG_PREFIX} Unexpected error updating expectation {expectation_id}: {e}"
                )

        self.logger.info(
            f"{LOG_PREFIX} Individual updates completed: {success_count} successful, {error_count} failed"
        )

    def _update_expectation(
        self, expectation_id: str, update_data: dict[str, Any]
    ) -> None:
        """Update a single expectation.

        Args:
            expectation_id: ID of the expectation to update.
            update_data: Update data to apply to the expectation.

        Raises:
            ExpectationUpdateError: If the update fails.

        """
        self.logger.debug(
            f"{LOG_PREFIX} Updating individual expectation: {expectation_id}"
        )

        try:
            self.oaev_api.inject_expectation.update(
                inject_expectation_id=expectation_id,
                inject_expectation=update_data,
            )
            self.logger.debug(
                f"{LOG_PREFIX} Successfully updated expectation {expectation_id}"
            )

        except Exception as individual_error:
            raise ExpectationUpdateError(
                f"Failed to update expectation {expectation_id}: {individual_error}"
            ) from individual_error

    def _fetch_expectations_with_timeout(
        self,
    ) -> list[DetectionExpectation | PreventionExpectation]:
        """Keep fetching expectations until we get ones with end_date or 5min timeout.

        Continuously fetches expectations from OpenBAS until either:
        1. Expectations with end_date signatures are found, or
        2. The 5-minute timeout is reached.

        Returns:
            List of expectations that meet the criteria.

        """
        start_time = datetime.utcnow()
        timeout = timedelta(minutes=FETCH_TIMEOUT_MINUTES)
        attempt_count = 0

        self.logger.debug(
            f"{LOG_PREFIX} Fetching expectations for collector: {self.collector_id}"
        )

        while (datetime.utcnow() - start_time) < timeout:
            attempt_count += 1
            elapsed = datetime.utcnow() - start_time

            self.logger.debug(
                f"{LOG_PREFIX} Expectation fetch attempt {attempt_count} (elapsed: {elapsed.total_seconds():.1f}s)"
            )

            try:
                expectations = (
                    self.oaev_api.inject_expectation.expectations_models_for_source(
                        source_id=self.collector_id
                    )
                )
            except Exception as e:
                self.logger.warning(
                    f"{LOG_PREFIX} Error fetching expectations: {e}, retrying..."
                )
                self._interruptible_sleep(SLEEP_INTERVAL_SECONDS)
                continue

            if not expectations:
                self.logger.debug(
                    f"{LOG_PREFIX} No expectations found, waiting {SLEEP_INTERVAL_SECONDS}s before retry..."
                )
                self._interruptible_sleep(SLEEP_INTERVAL_SECONDS)
                continue

            self.logger.debug(
                f"{LOG_PREFIX} Found {len(expectations)} expectations, checking for end_date..."
            )

            has_end_date = self._check_for_end_date(expectations)

            if has_end_date:
                self.logger.info(
                    f"{LOG_PREFIX} Found {len(expectations)} expectations with end_date after {attempt_count} attempts"
                )
                return expectations  # type: ignore[no-any-return]

            self.logger.debug(
                f"{LOG_PREFIX} No end_date found in expectations, waiting {SLEEP_INTERVAL_SECONDS}s before retry..."
            )
            self._interruptible_sleep(SLEEP_INTERVAL_SECONDS)

        self.logger.warning(
            f"{LOG_PREFIX} Timeout reached after {attempt_count} attempts ({timeout.total_seconds()}s)"
        )

        try:
            final_expectations = (
                self.oaev_api.inject_expectation.expectations_models_for_source(
                    source_id=self.collector_id
                )
            )
        except Exception as e:
            self.logger.error(f"{LOG_PREFIX} Final expectations fetch failed: {e}")
            return []

        if final_expectations:
            self.logger.info(
                f"{LOG_PREFIX} Processing {len(final_expectations)} expectations without end_date requirement"
            )
        return final_expectations or []

    def _check_for_end_date(
        self, expectations: list[DetectionExpectation | PreventionExpectation]
    ) -> bool:
        """Check if any expectation has end_date signature.

        Args:
            expectations: List of expectations to check.

        Returns:
            True if any expectation contains an end_date signature.

        """
        try:
            for expectation in expectations:
                if hasattr(expectation, "inject_expectation_signatures"):
                    for signature in expectation.inject_expectation_signatures:
                        if signature.type == SignatureTypes.SIG_TYPE_END_DATE:
                            return True
            return False
        except Exception as e:
            self.logger.debug(f"{LOG_PREFIX} Error checking for end_date: {e}")
            return False

    def _interruptible_sleep(self, seconds: int) -> None:
        """Sleep for the given seconds, but check for interrupts every second.

        Provides interruptible sleep that responds to KeyboardInterrupt (Ctrl+C)
        and logs progress for longer sleep periods.

        Args:
            seconds: Number of seconds to sleep.

        """
        if seconds <= 0:
            return

        self.logger.debug(
            f"{LOG_PREFIX} Sleeping for {seconds} seconds (interruptible)..."
        )

        for i in range(seconds):
            try:
                time.sleep(1)

                if (
                    seconds >= SLEEP_INTERVAL_SECONDS
                    and (i + 1) % PROGRESS_LOG_INTERVAL == 0
                ):
                    self.logger.debug(
                        f"{LOG_PREFIX} Sleep progress: {i + 1}/{seconds} seconds"
                    )
            except KeyboardInterrupt:
                import sys

                self.logger.info(f"{LOG_PREFIX} Sleep interrupted by user (Ctrl+C)")
                sys.exit(0)
