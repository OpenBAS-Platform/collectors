"""Protocol defining the interface for expectation service providers."""

from typing import Any, Protocol

from pyobas.apis.inject_expectation.model import (  # type: ignore[import-untyped]
    DetectionExpectation,
    PreventionExpectation,
)
from pyobas.helpers import OpenBASDetectionHelper  # type: ignore[import-untyped]
from pyobas.signatures.types import SignatureTypes  # type: ignore[import-untyped]

from .models import ExpectationResult


class ExpectationServiceProvider(Protocol):
    """Protocol defining the interface for expectation service providers."""

    def get_supported_signatures(self) -> list[SignatureTypes]:
        """Get list of signature types this provider supports.

        Returns:
            List of SignatureTypes that this provider can handle.

        """
        ...

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
        ...

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
        ...

    def handle_batch_expectations(
        self, expectations: list[Any], detection_helper: OpenBASDetectionHelper
    ) -> list[ExpectationResult]:
        """Handle a batch of expectations efficiently.

        Args:
            expectations: List of expectations to process in batch.
            detection_helper: OpenBAS detection helper instance.

        Returns:
            List of ExpectationResult objects for each processed expectation.

        """
        ...
