"""SentinelOne Expectation Service Provider.

This module contains all the SentinelOne-specific logic for handling expectations.
It implements the service provider protocol and defines which signatures to support,
how to fetch data, and how to process expectations.
"""

import logging
from typing import Any

from pyobas.apis.inject_expectation.model import (  # type: ignore[import-untyped]
    DetectionExpectation,
    PreventionExpectation,
)
from pyobas.helpers import OpenBASDetectionHelper  # type: ignore[import-untyped]
from pyobas.signatures.types import SignatureTypes  # type: ignore[import-untyped]

from ..collector.models import ExpectationResult
from ..models.configs.config_loader import ConfigLoader
from .client_api import SentinelOneClientAPI
from .converter import Converter
from .exception import (
    SentinelOneAPIError,
    SentinelOneConfigurationError,
    SentinelOneDataConversionError,
    SentinelOneExpectationError,
    SentinelOneMatchingError,
    SentinelOneNetworkError,
    SentinelOneNoAlertsFoundError,
    SentinelOneNoMatchingAlertsError,
    SentinelOneServiceError,
    SentinelOneValidationError,
)

LOG_PREFIX = "[SentinelOneExpectationService]"


class SentinelOneExpectationService:
    """SentinelOne-specific service provider for expectation handling.

    This class contains all the business logic specific to SentinelOne:
    - Which signature types to support
    - How to fetch data from SentinelOne
    - How to validate expectations against data
    - How to handle batching and optimization
    """

    SUPPORTED_SIGNATURES = [
        SignatureTypes.SIG_TYPE_PARENT_PROCESS_NAME,
        SignatureTypes.SIG_TYPE_START_DATE,
        SignatureTypes.SIG_TYPE_END_DATE,
    ]

    def __init__(self, config: ConfigLoader | None = None) -> None:
        """Initialize the SentinelOne service provider.

        Args:
            config: Configuration loader instance for service settings.

        Raises:
            SentinelOneValidationError: If config is None.
            SentinelOneConfigurationError: If service components initialization fails.

        """
        if config is None:
            raise SentinelOneValidationError(
                "Config is required for expectation service"
            )

        self.logger = logging.getLogger(__name__)
        self.config = config

        try:
            self.logger.debug(
                f"{LOG_PREFIX} Initializing SentinelOne service components..."
            )
            self.client_api = SentinelOneClientAPI(config)
            self.converter = Converter()
            self.logger.info(
                f"{LOG_PREFIX} SentinelOne expectation service initialized successfully"
            )
        except (SentinelOneValidationError, SentinelOneConfigurationError):
            raise
        except Exception as e:
            raise SentinelOneConfigurationError(
                f"Failed to initialize SentinelOne service components: {e}"
            ) from e

        if (
            hasattr(config, "sentinelone")
            and hasattr(config.sentinelone, "time_window")
            and config.sentinelone.time_window
        ):
            self.time_window = config.sentinelone.time_window
            self.logger.debug(
                f"{LOG_PREFIX} Using configured time window: {self.time_window}"
            )
        else:
            from datetime import timedelta

            self.time_window = timedelta(days=1)
            self.logger.warning(
                f"{LOG_PREFIX} No time_window configured, using default 1 day"
            )

    def get_supported_signatures(self) -> list[SignatureTypes]:
        """Get the signature types this service supports.

        Returns:
            List of SignatureTypes that this service can process.

        """
        self.logger.debug(
            f"{LOG_PREFIX} Returning {len(self.SUPPORTED_SIGNATURES)} supported signature types"
        )
        return self.SUPPORTED_SIGNATURES

    def handle_batch_expectations(
        self,
        expectations: list[DetectionExpectation | PreventionExpectation],
        detection_helper: OpenBASDetectionHelper,
    ) -> list[ExpectationResult]:
        """Handle a batch of expectations.

        Processes each expectation individually and collects results,
        handling errors gracefully for individual expectations.

        Args:
            expectations: List of expectations to process.
            detection_helper: OpenBAS detection helper.

        Returns:
            List of ExpectationResult objects.

        Raises:
            SentinelOneExpectationError: If batch processing fails.

        """
        if not expectations:
            self.logger.info(f"{LOG_PREFIX} No expectations to process")
            return []

        try:
            self.logger.info(
                f"{LOG_PREFIX} Starting batch processing of {len(expectations)} expectations"
            )

            all_results_with_expectations_associated = []

            for i, expectation in enumerate(expectations, 1):
                expectation_id = str(expectation.inject_expectation_id)
                self.logger.debug(
                    f"{LOG_PREFIX} Processing expectation {i}/{len(expectations)}: {expectation_id}"
                )

                try:
                    result = self.process_expectation(expectation, detection_helper)
                    if result.is_valid:
                        self.logger.debug(
                            f"{LOG_PREFIX} Expectation {expectation_id} processed successfully"
                        )
                    else:
                        self.logger.debug(
                            f"{LOG_PREFIX} Expectation {expectation_id} failed validation"
                        )

                except SentinelOneServiceError as e:
                    self.logger.warning(
                        f"{LOG_PREFIX} SentinelOne service error for expectation {expectation_id}: {e}"
                    )
                    result = self._create_error_result_object(e, expectation)
                except Exception as e:
                    self.logger.error(
                        f"{LOG_PREFIX} Unexpected error processing expectation {expectation_id}: {e}"
                    )
                    result = self._create_error_result_object(
                        SentinelOneExpectationError(f"Unexpected error: {e}"),
                        expectation,
                    )

                all_results_with_expectations_associated.append(result)

            valid_count = sum(
                1 for r in all_results_with_expectations_associated if r.is_valid
            )
            invalid_count = len(all_results_with_expectations_associated) - valid_count

            self.logger.info(
                f"{LOG_PREFIX} Batch expectation processing: processed {len(expectations)} items -> {len(all_results_with_expectations_associated)} results"
            )
            self.logger.info(
                f"{LOG_PREFIX} Batch processing completed: {valid_count} valid, {invalid_count} invalid"
            )

            return all_results_with_expectations_associated

        except Exception as e:
            raise SentinelOneExpectationError(
                f"Error in handle_batch_expectations: {e}"
            ) from e

    def process_expectation(
        self,
        expectation: DetectionExpectation | PreventionExpectation,
        detection_helper: OpenBASDetectionHelper,
    ) -> ExpectationResult:
        """Process a single expectation based on its type.

        Args:
            expectation: The expectation to process (Detection or Prevention).
            detection_helper: OpenBAS detection helper instance.

        Returns:
            ExpectationResult containing the processing outcome.

        Raises:
            SentinelOneExpectationError: If expectation type is unsupported.

        """
        expectation_id = str(expectation.inject_expectation_id)

        if isinstance(expectation, DetectionExpectation):
            self.logger.debug(
                f"{LOG_PREFIX} Processing detection expectation: {expectation_id}"
            )
            return self.handle_detection_expectation(expectation, detection_helper)
        elif isinstance(expectation, PreventionExpectation):
            self.logger.debug(
                f"{LOG_PREFIX} Processing prevention expectation: {expectation_id}"
            )
            return self.handle_prevention_expectation(expectation, detection_helper)
        else:
            self.logger.error(
                f"{LOG_PREFIX} Unsupported expectation type for {expectation_id}: {type(expectation).__name__}"
            )
            raise SentinelOneExpectationError(
                f"Unsupported expectation type: {type(expectation).__name__}"
            )

    def handle_detection_expectation(
        self,
        expectation: DetectionExpectation,
        detection_helper: OpenBASDetectionHelper,
    ) -> ExpectationResult:
        """Handle a detection expectation.

        Args:
            expectation: The detection expectation to process.
            detection_helper: OpenBAS detection helper instance.

        Returns:
            ExpectationResult containing the processing outcome.

        """
        result_dict = self._handle_expectation(
            expectation, detection_helper, "detection"
        )
        return self._convert_dict_to_result(result_dict, expectation)

    def handle_prevention_expectation(
        self,
        expectation: PreventionExpectation,
        detection_helper: OpenBASDetectionHelper,
    ) -> ExpectationResult:
        """Handle a prevention expectation.

        Args:
            expectation: The prevention expectation to process.
            detection_helper: OpenBAS detection helper instance.

        Returns:
            ExpectationResult containing the processing outcome.

        """
        result_dict = self._handle_expectation(
            expectation, detection_helper, "prevention"
        )
        return self._convert_dict_to_result(result_dict, expectation)

    def _handle_expectation(
        self,
        expectation: DetectionExpectation | PreventionExpectation,
        detection_helper: OpenBASDetectionHelper,
        expectation_type: str,
    ) -> dict[str, Any]:
        """Core logic for handling expectations.

        Args:
            expectation: The expectation to process.
            detection_helper: OpenBAS detection helper instance.
            expectation_type: Type of expectation ('detection' or 'prevention').

        Returns:
            Dictionary containing processing results.

        Raises:
            SentinelOneExpectationError: If expectation processing fails.

        """
        expectation_id = expectation.inject_expectation_id

        try:
            self.logger.debug(
                f"{LOG_PREFIX} Starting {expectation_type} expectation processing: {expectation_id}"
            )

            self.logger.debug(f"{LOG_PREFIX} Extracting signatures from expectation...")
            search_signatures, matching_signatures = self._extract_signatures(
                expectation
            )
            self.logger.debug(
                f"{LOG_PREFIX} Extracted {len(search_signatures)} search signatures, {len(matching_signatures)} matching signatures"
            )

            self.logger.debug(
                f"{LOG_PREFIX} Fetching SentinelOne data for {expectation_type} expectation..."
            )
            sentinelone_data = self.client_api.fetch_signatures(
                search_signatures, expectation_type
            )
            self.logger.debug(
                f"{LOG_PREFIX} Fetched {len(sentinelone_data)} data items from SentinelOne"
            )

            self.logger.debug(
                f"{LOG_PREFIX} Converting SentinelOne data to OAEV format..."
            )
            oaev_data = self.converter.convert_data_to_oaev_data(sentinelone_data)
            self.logger.debug(
                f"{LOG_PREFIX} Converted to {len(oaev_data)} OAEV data items"
            )

            self.logger.debug(
                f"{LOG_PREFIX} Matching data against expectation signatures..."
            )
            result = self._match(
                oaev_data, matching_signatures, detection_helper, expectation_type
            )

            return result

        except (
            SentinelOneServiceError,
            SentinelOneAPIError,
            SentinelOneNetworkError,
            SentinelOneDataConversionError,
        ):
            raise
        except Exception as e:
            raise SentinelOneExpectationError(
                f"Unexpected error processing expectation: {e}"
            ) from e

    def _extract_signatures(
        self, expectation: DetectionExpectation | PreventionExpectation
    ) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
        """Extract and filter signatures from expectation.

        Args:
            expectation: The expectation to extract signatures from.

        Returns:
            Tuple of (search_signatures, matching_signatures):
            - search_signatures: signatures for API query building
            - matching_signatures: signatures for alert matching (excludes date metadata)

        Raises:
            SentinelOneExpectationError: If signature extraction fails.

        """
        try:
            all_signatures = [
                {"type": sig.type.value, "value": sig.value}
                for sig in expectation.inject_expectation_signatures
            ]
            self.logger.debug(
                f"{LOG_PREFIX} Found {len(all_signatures)} total signatures in expectation"
            )

            search_signatures = [
                sig
                for sig in all_signatures
                if sig["type"] in [s.value for s in self.SUPPORTED_SIGNATURES]
            ]

            date_signature_types = [
                SignatureTypes.SIG_TYPE_START_DATE.value,
                SignatureTypes.SIG_TYPE_END_DATE.value,
            ]
            matching_signatures = [
                sig
                for sig in search_signatures
                if sig["type"] not in date_signature_types
            ]

            self.logger.debug(
                f"{LOG_PREFIX} Filtered to {len(search_signatures)} search signatures and {len(matching_signatures)} matching signatures"
            )

            return search_signatures, matching_signatures

        except Exception as e:
            raise SentinelOneExpectationError(
                f"Failed to extract signatures from expectation: {e}"
            ) from e

    def _match(
        self,
        oaev_data: list[dict[str, Any]],
        matching_signatures: list[dict[str, str]],
        detection_helper: OpenBASDetectionHelper,
        expectation_type: str,
    ) -> dict[str, Any]:
        """Match OAEV data against expectation signatures.

        Args:
            oaev_data: List of OAEV formatted data.
            matching_signatures: Signatures to match against.
            detection_helper: OpenBAS detection helper.
            expectation_type: Type of expectation ('detection' or 'prevention').

        Returns:
            Result dictionary with match status and matching data.

        Raises:
            SentinelOneNoAlertsFoundError: If no data available for matching.
            SentinelOneNoMatchingAlertsError: If no matching alerts found.
            SentinelOneMatchingError: If matching process fails.

        """
        try:
            if not oaev_data:
                self.logger.debug(f"{LOG_PREFIX} No OAEV data available for matching")
                raise SentinelOneNoAlertsFoundError("No data available for matching")

            self.logger.debug(
                f"{LOG_PREFIX} Attempting to match {len(oaev_data)} data items against {len(matching_signatures)} signatures"
            )

            for i, data_item in enumerate(oaev_data):
                self.logger.debug(
                    f"{LOG_PREFIX} Matching data item {i + 1}/{len(oaev_data)}"
                )

                available_signatures = [
                    sig for sig in matching_signatures if sig["type"] in data_item
                ]

                self.logger.debug(
                    f"{LOG_PREFIX} Data item {i + 1} has {len(available_signatures)} available signatures out of {len(matching_signatures)}"
                )

                if available_signatures:
                    try:
                        self.logger.debug(
                            f"{LOG_PREFIX} Testing match for data item {i + 1} with {len(available_signatures)} signatures"
                        )

                        if detection_helper.match_alert_elements(
                            available_signatures, data_item
                        ):
                            self.logger.debug(
                                f"{LOG_PREFIX} Match found for data item {i + 1}!"
                            )

                            if expectation_type == "prevention":
                                has_threat_id = any(
                                    "threat_id" in item for item in oaev_data
                                )
                                if not has_threat_id:
                                    self.logger.debug(
                                        f"{LOG_PREFIX} Prevention match found but no threat_id present in any data item, continuing search"
                                    )
                                    continue
                                else:
                                    self.logger.debug(
                                        f"{LOG_PREFIX} Prevention match confirmed with threat_id present"
                                    )
                                    threat_entries = [
                                        item
                                        for item in oaev_data
                                        if "threat_id" in item
                                    ]
                                    oaev_data = threat_entries
                                    data_item = threat_entries[0]

                            self.logger.info(
                                f"{LOG_PREFIX} Successful match found for {expectation_type} expectation"
                            )
                            self.logger.debug(
                                f"{LOG_PREFIX} Matching data: {data_item}"
                            )

                            result = {
                                "is_valid": True,
                                "matching_data": [data_item],
                                "total_data_found": len(oaev_data),
                            }

                            return result
                        else:
                            self.logger.debug(
                                f"{LOG_PREFIX} No match for data item {i + 1}"
                            )
                            continue
                    except Exception as e:
                        self.logger.error(
                            f"{LOG_PREFIX} Error during matching for data item {i + 1}: {e}"
                        )
                        raise SentinelOneNoMatchingAlertsError() from e
                else:
                    self.logger.debug(
                        f"{LOG_PREFIX} Data item {i + 1} has no available signatures to match against"
                    )

            self.logger.info(
                f"{LOG_PREFIX} No matching alerts found after checking {len(oaev_data)} data items"
            )
            raise SentinelOneNoMatchingAlertsError()

        except (
            SentinelOneServiceError,
            SentinelOneNoAlertsFoundError,
            SentinelOneNoMatchingAlertsError,
        ):
            raise
        except Exception as e:
            raise SentinelOneMatchingError() from e

    def _create_error_result(
        self,
        error: SentinelOneServiceError,
        expectation: DetectionExpectation | PreventionExpectation | None = None,
    ) -> dict[str, Any]:
        """Create an error result dictionary from a SentinelOne service error.

        Args:
            error: The SentinelOne service error that occurred.
            expectation: Optional expectation object that caused the error.

        Returns:
            Dictionary containing error details and metadata.

        """
        result = {
            "is_valid": False,
            "error": str(error),
            "error_type": error.__class__.__name__,
        }

        if hasattr(error, "status_code") and error.status_code:
            result["status_code"] = error.status_code

        if hasattr(error, "response_data") and error.response_data:
            result["response_data"] = error.response_data

        if expectation:
            result["expectation"] = expectation
            result["expectation_id"] = str(expectation.inject_expectation_id)

        return result

    def _create_error_result_object(
        self,
        error: SentinelOneServiceError,
        expectation: DetectionExpectation | PreventionExpectation | None = None,
    ) -> ExpectationResult:
        """Create an ExpectationResult object from a SentinelOne service error.

        Args:
            error: The SentinelOne service error that occurred.
            expectation: Optional expectation object that caused the error.

        Returns:
            ExpectationResult object with error details.

        """
        expectation_id = (
            str(expectation.inject_expectation_id) if expectation else "unknown"
        )

        error_message = str(error)
        if hasattr(error, "status_code") and error.status_code:
            error_message += f" (Status: {error.status_code})"

        return ExpectationResult(
            expectation_id=expectation_id,
            is_valid=False,
            expectation=expectation,
            error_message=error_message,
        )

    def _convert_dict_to_result(
        self,
        result_dict: dict[str, Any],
        expectation: DetectionExpectation | PreventionExpectation,
    ) -> ExpectationResult:
        """Convert a dictionary result to ExpectationResult object.

        Args:
            result_dict: Dictionary containing processing results.
            expectation: The expectation that was processed.

        Returns:
            ExpectationResult object with structured data.

        """
        return ExpectationResult(
            expectation_id=str(expectation.inject_expectation_id),
            is_valid=result_dict.get("is_valid", False),
            expectation=expectation,
            matched_alerts=result_dict.get("matching_data"),
            error_message=result_dict.get("error"),
        )

    def get_service_info(self) -> dict[str, Any]:
        """Get information about this service provider.

        Returns:
            Dictionary containing service metadata and capabilities.

        """
        info = {
            "service_name": "SentinelOne",
            "supported_signatures": [sig.value for sig in self.SUPPORTED_SIGNATURES],
            "supports_detection": True,
            "supports_prevention": True,
            "description": f"SentinelOne EDR expectation validation service ({len(self.SUPPORTED_SIGNATURES)} signature types)",
        }
        self.logger.debug(f"{LOG_PREFIX} Service info: {info}")
        return info
