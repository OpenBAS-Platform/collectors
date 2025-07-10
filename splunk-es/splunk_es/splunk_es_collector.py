"""
Splunk ES Collector Daemon.

This module provides the main collector daemon that orchestrates
the Splunk ES expectation validation workflow using the pyobas
CollectorDaemon framework.
"""

import time
from typing import Generator

from pyobas.daemons import CollectorDaemon
from pyobas.helpers import OpenBASDetectionHelper
from pyobas.signatures.types import SignatureTypes

from splunk_es.exceptions import (
    SplunkESConfigurationError,
    SplunkESError,
)

from splunk_es.splunk_es_client import SplunkESClient
from splunk_es.splunk_es_configuration import SplunkESConfiguration
from splunk_es.splunk_es_models import SplunkSearchResponse
from splunk_es.expectation_manager import ExpectationManager


class SplunkESCollector(CollectorDaemon):
    """
    Splunk ES Collector implementation extending CollectorDaemon.

    This collector validates OpenAEV expectations by querying Splunk ES
    for matching security alerts and updates expectations accordingly.
    """

    def __init__(self):
        """
        Initialize Splunk ES collector.

        Raises:
            SplunkESConfigurationError: If configuration is invalid
        """
        try:
            self.splunk_config = SplunkESConfiguration()
            self.splunk_config.validate()

            super().__init__(
                configuration=self.splunk_config,
                callback=self._process_expectations_callback,
            )

            self.splunk_client = None
            self.expectation_manager = None
            self.detection_helper = None

            self.logger.info("Splunk ES Collector initialized successfully")

        except Exception as e:
            raise SplunkESConfigurationError(f"Failed to initialize collector: {e}") from e

    def _setup(self):
        """
        Set up collector components before starting the main loop.

        This method is called once by the base CollectorDaemon before
        starting the periodic execution loop.

        Raises:
            SplunkESError: If setup fails
        """
        try:
            self.logger.info("Setting up Splunk ES Collector components")

            super()._setup()

            splunk_config = self.splunk_config.get_splunk_config()
            self.splunk_client = SplunkESClient(splunk_config, self.logger)

            self.expectation_manager = ExpectationManager(self.logger, self.api, self.get_id())

            relevant_signature_types = [
                SignatureTypes.SIG_TYPE_SOURCE_IPV4,
                SignatureTypes.SIG_TYPE_TARGET_IPV4,
            ]

            self.detection_helper = OpenBASDetectionHelper(
                logger=self.logger, relevant_signatures_types=relevant_signature_types
            )

            self.logger.info("Splunk ES Collector setup completed successfully")

        except Exception as e:
            raise SplunkESError(f"Setup failed: {e}") from e

    def _process_expectations_callback(self) -> dict:
        """
        Main callback function for processing expectations.

        This method is called periodically by the CollectorDaemon and
        orchestrates the entire expectation validation workflow.

        Returns:
            Dict containing processing results

        Raises:
            SplunkESError: If processing fails
        """
        try:
            self.logger.info("Starting Splunk ES expectation processing cycle")
            start_time = time.time()

            batch_generator = self.expectation_manager.fetch_expectations_in_batches()
            processed_generator = self._process_expectations_in_batches(batch_generator)
            results = self.expectation_manager.update_expectations_in_batches(processed_generator)

            processing_time = time.time() - start_time

            valid_count = len(results.get("valid_expectations", []))
            invalid_count = len(results.get("invalid_expectations", []))
            total_count = valid_count + invalid_count

            if total_count > 0:
                self.logger.info(
                    f"Processing cycle completed in {processing_time:.2f}s - "
                    f"Valid: {valid_count}, Invalid: {invalid_count}, Total: {total_count}"
                )
            else:
                self.logger.info(
                    f"Processing cycle completed in {processing_time:.2f}s - "
                    f"No expectations found for processing"
                )
                self.logger.info(f"Next cycle in {self._configuration.get('collector_period')}s")

            return results

        except Exception as e:
            self.logger.error(f"Expectation processing failed: {e}")
            raise SplunkESError(f"Processing cycle failed: {e}") from e

    def _process_expectations_in_batches(
        self, batch_generator: Generator[list[tuple[str, object, dict]], None, None]
    ) -> Generator[dict[str, object], None, None]:
        """
        Process all batches of expectations with Splunk ES validation.

        Args:
            batch_generator: Generator yielding batches of expectation tuples

        Yields:
            Dict containing processed expectation results
        """
        try:
            self.logger.info("Processing expectations in batches with Splunk ES validation")

            total_valid = 0
            total_invalid = 0
            total_processed = 0
            batch_count = 0

            for batch in batch_generator:
                batch_count += 1
                batch_valid = 0
                batch_invalid = 0

                self.logger.info(f"Processing batch {batch_count} with {len(batch)} expectations")

                try:
                    for result in self._process_single_batch(batch):
                        total_processed += 1
                        if result["is_valid"]:
                            batch_valid += 1
                            total_valid += 1
                        else:
                            batch_invalid += 1
                            total_invalid += 1

                        yield result

                    self.logger.info(
                        f"Batch {batch_count} complete: {batch_valid} valid, {batch_invalid} invalid"
                    )

                except Exception as e:
                    self.logger.error(f"Failed to process batch {batch_count}: {e}")
                    continue
                finally:
                    self.expectation_manager._cleanup_memory(batch)

            self.logger.info(
                f"All batches processed: {total_processed} total expectations, "
                f"{total_valid} valid, {total_invalid} invalid in {batch_count} batches"
            )

        except Exception as e:
            self.logger.error(f"Batch processing failed: {e}")
            raise

    def _process_single_batch(
        self, batch: list[tuple[str, object, dict]]
    ) -> Generator[dict[str, object], None, None]:
        """
        Process a single batch of expectations with Splunk ES queries.

        Args:
            batch: List of expectation tuples for this batch

        Yields:
            Dict containing processed expectation results
        """
        try:
            self.logger.debug(f"Processing single batch of {len(batch)} expectations")

            batch_source_ips, batch_target_ips, ip_expectations = (
                self.expectation_manager.gather_batch_ips(batch)
            )

            if not ip_expectations:
                self.logger.debug("No IP-based expectations in this batch")
                return

            alerts = self._execute_batch_splunk_query(batch_source_ips, batch_target_ips)

            self.expectation_manager._cleanup_memory(batch_source_ips, batch_target_ips)

            for expectation_type, expectation, ip_data in ip_expectations:
                source_ips = ip_data.get("source_ips", [])
                target_ips = ip_data.get("target_ips", [])

                ip_summary = []
                if source_ips:
                    ip_summary.append(f"Source IPs: {source_ips}")
                if target_ips:
                    ip_summary.append(f"Target IPs: {target_ips}")

                self.logger.debug(
                    f"Processing expectation {expectation.inject_expectation_id} "
                    f"with {', '.join(ip_summary)}"
                )

                is_valid = self._validate_expectation_against_alerts(expectation, alerts)

                yield {
                    "expectation": expectation,
                    "source_ips": source_ips,
                    "target_ips": target_ips,
                    "all_ips": ip_data.get("all_ips", []),
                    "is_valid": is_valid,
                    "expectation_id": str(expectation.inject_expectation_id),
                }

            self.expectation_manager._cleanup_memory(alerts, ip_expectations)

        except Exception as e:
            self.logger.error(f"Single batch processing failed: {e}")
            raise

    def _execute_batch_splunk_query(
        self, batch_source_ips: set[str], batch_target_ips: set[str]
    ) -> SplunkSearchResponse:
        """
        Execute a Splunk query for a single batch of IPs.

        Args:
            batch_source_ips: Set of source IPs for this batch
            batch_target_ips: Set of target IPs for this batch

        Returns:
            List of alert dictionaries from Splunk
        """
        try:
            if not batch_source_ips and not batch_target_ips:
                self.logger.debug("No IPs in batch, skipping Splunk query")
                return []

            self.logger.debug(
                f"Executing Splunk query for batch with {len(batch_source_ips)} source IPs "
                f"and {len(batch_target_ips)} target IPs"
            )

            source_ip_list = list(batch_source_ips)
            target_ip_list = list(batch_target_ips)

            spl_query = self.splunk_client.build_ip_search_query(source_ip_list, target_ip_list)
            alerts = self.splunk_client.execute_query(spl_query)

            self.logger.debug(f"Batch query returned {len(alerts.results)} alerts")

            self.expectation_manager._cleanup_memory(source_ip_list, target_ip_list)

            return alerts

        except Exception as e:
            self.logger.error(f"Batch Splunk query failed: {e}")
            raise

    def _validate_expectation_against_alerts(self, expectation: object, alerts: SplunkSearchResponse) -> bool:
        """
        Validate a single expectation against alerts using OpenBAS detection helper.

        Args:
            expectation: The expectation object
            alerts: List of alerts from Splunk

        Returns:
            bool: True if expectation matches any alert, False otherwise
        """
        try:
            self.logger.debug(
                f"Validating expectation {expectation.inject_expectation_id} "
                f"against {len(alerts.results)} alerts"
            )

            expectation_signatures = [
                {"type": sig.type.value, "value": sig.value}
                for sig in expectation.inject_expectation_signatures
            ]

            for alert in alerts.results:
                alert_data = self.splunk_client.convert_alert_to_detection_data(alert)

                if self.detection_helper.match_alert_elements(expectation_signatures, alert_data):
                    self.logger.debug(
                        f"Expectation {expectation.inject_expectation_id} matched alert"
                    )
                    return True

            self.logger.debug(
                f"Expectation {expectation.inject_expectation_id} found no matching alerts"
            )
            return False

        except Exception as e:
            self.logger.error(
                f"Error validating expectation {expectation.inject_expectation_id}: {e}"
            )
            return False
