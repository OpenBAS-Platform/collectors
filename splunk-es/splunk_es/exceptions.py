"""
Custom exceptions for Splunk ES Collector.

This module defines specific exceptions used throughout the Splunk ES collector
to provide clear error handling and debugging information.
"""

from pyobas.exceptions import OpenBASError


class SplunkESError(OpenBASError):
    """Base exception for all Splunk ES collector errors."""

    pass


class SplunkESConfigurationError(SplunkESError):
    """Raised when there are configuration-related errors."""

    pass


class SplunkESConnectionError(SplunkESError):
    """Raised when connection to Splunk ES fails."""

    pass


class SplunkESQueryError(SplunkESError):
    """Raised when SPL query execution fails."""

    pass


class SplunkESAuthenticationError(SplunkESError):
    """Raised when Splunk ES authentication fails."""

    pass


class SplunkESExpectationError(SplunkESError):
    """Raised when expectation processing fails."""

    pass


class SplunkESAlertProcessingError(SplunkESError):
    """Raised when alert processing fails."""

    pass


class SplunkESBatchProcessingError(SplunkESError):
    """Raised when batch processing fails."""

    pass
