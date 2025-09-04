"""
Expectation Manager for OpenAEV Collectors.

This module provides a generic expectation manager that handles batch processing
of expectations. It is designed to be agnostic of the specific data source
(Splunk, Elastic, etc.) and focuses purely on expectation management logic.
"""

import gc
from typing import Generator

from pyobas.apis.inject_expectation.model import DetectionExpectation
from pyobas.signatures.types import SignatureTypes

from splunk_es.exceptions import SplunkESExpectationError

# Constants
BATCH_SIZE = 200


class ExpectationManager:
    """
    Generic manager for processing OpenAEV expectations in batches.

    This manager is data source agnostic and handles only expectation
    fetching, batching, and updating. The actual validation logic
    is delegated to the caller.
    """

    def __init__(self, logger, api, collector_id):
        """
        Initialize expectation manager.

        Args:
            logger: Logger instance
            api: OpenBAS API client
            collector_id: ID of the collector
        """
        self.logger = logger
        self.api = api
        self.collector_id = collector_id
        self.batch_size = BATCH_SIZE

    def fetch_expectations_in_batches(
        self,
    ) -> Generator[list[tuple[str, object, dict]], None, None]:
        """
        Fetch expectations in batches to optimize memory usage.

        Yields:
            List of expectation tuples for each batch: (type, expectation, ip_data)
        """
        try:
            self.logger.info("Fetching expectations from OpenAEV in batches")

            all_expectations = self.api.inject_expectation.expectations_models_for_source(
                source_id=self.collector_id
            )

            total_expectations = len(all_expectations)
            self.logger.info(f"Found {total_expectations} total expectations")

            if total_expectations == 0:
                return

            batch_count = 0
            current_batch = []
            detection_count = 0
            prevention_count = 0
            detection_no_ip_count = 0

            for i, expectation in enumerate(all_expectations):
                self.logger.debug(
                    f"Processing expectation {i + 1}/{total_expectations}: {expectation}"
                )

                if not isinstance(expectation, DetectionExpectation):
                    expectation.update(False, self.collector_id, metadata={})
                    self.logger.debug(f"Skipping non-detection expectation: {type(expectation)}")
                    prevention_count += 1
                    continue

                source_ips = [
                    sig.value
                    for sig in expectation.inject_expectation_signatures
                    if sig.type == SignatureTypes.SIG_TYPE_SOURCE_IPV4
                ]
                target_ips = [
                    sig.value
                    for sig in expectation.inject_expectation_signatures
                    if sig.type == SignatureTypes.SIG_TYPE_TARGET_IPV4
                ]

                ip_data = {
                    "source_ips": source_ips,
                    "target_ips": target_ips,
                    "all_ips": source_ips + target_ips,
                }

                if source_ips or target_ips:
                    detection_count += 1
                    current_batch.append(("ip", expectation, ip_data))
                else:
                    detection_no_ip_count += 1
                    expectation.update(False, self.collector_id, metadata={})
                    current_batch.append(("non_ip", expectation, {}))

                if len(current_batch) >= self.batch_size or i == total_expectations - 1:
                    if current_batch:
                        batch_count += 1
                        self.logger.info(
                            f"Yielding batch {batch_count} with {len(current_batch)} expectations "
                            f"(processed {i + 1}/{total_expectations})"
                        )
                        yield current_batch

                        self._cleanup_memory(current_batch)
                        current_batch = []

            self._cleanup_memory(all_expectations)

            self.logger.info(
                f"Completed fetching in {batch_count} batches: "
                f"{detection_count} DetectionExpectations with IPs processed, "
                f"{detection_no_ip_count} DetectionExpectations without IPs failed, "
                f"{prevention_count} non-DetectionExpectations skipped"
            )

        except Exception as e:
            raise SplunkESExpectationError(f"Failed to fetch expectations: {e}") from e

    def update_expectations_in_batches(
        self, processed_results: Generator[dict[str, object], None, None]
    ) -> dict[str, list[object]]:
        """
        Update expectations using batch processing with memory optimization.

        Args:
            processed_results: Generator yielding processed results with format:
                {
                    "expectation": expectation_object,
                    "is_valid": bool,
                    "expectation_id": str,
                    "source_ips": list[str],
                    "target_ips": list[str]
                }

        Returns:
            Dict containing lists of valid and invalid expectations
        """
        try:
            self.logger.info("Updating expectations in batches")

            valid_expectations = []
            invalid_expectations = []
            current_batch_updates = {}
            total_updates = 0

            for result in processed_results:
                expectation = result["expectation"]
                is_valid = result["is_valid"]
                expectation_id = result["expectation_id"]

                ip_details = []
                if result["source_ips"]:
                    ip_details.append(f"Source IPs: {result['source_ips']}")
                if result["target_ips"]:
                    ip_details.append(f"Target IPs: {result['target_ips']}")
                log_message_details = f" - {', '.join(ip_details)}" if ip_details else ""

                if is_valid:
                    valid_expectations.append(expectation)
                    update_data = {
                        "collector_id": self.collector_id,
                        "result": "Detected",
                        "is_success": True,
                    }
                    self.logger.info(f"Expectation {expectation_id} VALID{log_message_details}")
                else:
                    invalid_expectations.append(expectation)
                    update_data = {
                        "collector_id": self.collector_id,
                        "result": "Not Detected",
                        "is_success": False,
                    }
                    self.logger.info(f"Expectation {expectation_id} INVALID{log_message_details}")

                current_batch_updates[str(expectation_id)] = update_data
                total_updates += 1

                if len(current_batch_updates) >= self.batch_size:
                    self.logger.info(f"Batch updating {len(current_batch_updates)} expectations")
                    self.logger.debug(f"Batch update data: {current_batch_updates}")
                    self.api.inject_expectation.bulk_update(
                        inject_expectation_input_by_id=current_batch_updates
                    )

                    self._cleanup_memory(current_batch_updates)
                    current_batch_updates = {}

            if current_batch_updates:
                self.logger.info(f"Final batch updating {len(current_batch_updates)} expectations")
                self.logger.debug(f"Final batch update data: {current_batch_updates}")
                self.api.inject_expectation.bulk_update(
                    inject_expectation_input_by_id=current_batch_updates
                )
                self._cleanup_memory(current_batch_updates)

            self.logger.info(f"Successfully updated {total_updates} expectations in batches")

            return {
                "valid_expectations": valid_expectations,
                "invalid_expectations": invalid_expectations,
            }

        except Exception as e:
            raise SplunkESExpectationError(f"Failed to update expectations: {e}") from e

    def gather_batch_ips(
        self, batch: list[tuple[str, object, dict]]
    ) -> tuple[set[str], set[str], list[tuple[str, object, dict]]]:
        """
        Gather all unique source and target IPs from a single batch.

        Args:
            batch: List of expectation tuples in the batch

        Returns:
            Tuple of (batch_source_ips_set, batch_target_ips_set, ip_expectations_list)
        """
        batch_source_ips = set()
        batch_target_ips = set()
        ip_expectations = []

        for expectation_type, expectation, ip_data in batch:
            if expectation_type == "ip":
                ip_expectations.append((expectation_type, expectation, ip_data))
                batch_source_ips.update(ip_data.get("source_ips", []))
                batch_target_ips.update(ip_data.get("target_ips", []))

        return batch_source_ips, batch_target_ips, ip_expectations

    def _cleanup_memory(self, *objects):
        """Force cleanup of objects and garbage collection."""
        for obj in objects:
            if obj is not None:
                del obj
        gc.collect()
