"""
Splunk ES Collector for OpenAEV

This package provides a complete Splunk ES integration for OpenAEV expectation validation.
It validates expectations by querying Splunk ES for matching security alerts and updates
the expectations accordingly using production-ready patterns and error handling.

The collector is built on top of the pyobas framework and follows best practices for
code quality, error handling, and separation of concerns.

Key Components:
- SplunkESCollector: Main collector daemon extending CollectorDaemon
- SplunkESClient: Splunk ES API client for query execution and alert processing
- ExpectationManager: Handles batch processing of expectations with memory optimization
- SplunkESConfiguration: Configuration management with validation
- Custom exceptions for proper error handling

Usage:
    from splunk_es import SplunkESCollectorApp

    app = SplunkESCollectorApp("config.yml")
    exit_code = app.run()

Or run directly:
    python -m splunk_es.openaev_splunk_es
"""

from .exceptions import (
    SplunkESAlertProcessingError,
    SplunkESAuthenticationError,
    SplunkESBatchProcessingError,
    SplunkESConfigurationError,
    SplunkESConnectionError,
    SplunkESError,
    SplunkESExpectationError,
    SplunkESQueryError,
)
from .expectation_manager import ExpectationManager
from .openaev_splunk_es import (
    main,
)
from .splunk_es_client import SplunkESClient
from .splunk_es_configuration import SplunkESConfiguration

__version__ = "1.0.0"
__author__ = "OpenBAS Team"
__email__ = "contact@filigran.io"

__all__ = [
    # Main application
    "main",
    # Core components
    "SplunkESClient",
    "ExpectationManager",
    "SplunkESConfiguration",
    # Exceptions
    "SplunkESError",
    "SplunkESConfigurationError",
    "SplunkESConnectionError",
    "SplunkESQueryError",
    "SplunkESAuthenticationError",
    "SplunkESExpectationError",
    "SplunkESAlertProcessingError",
    "SplunkESBatchProcessingError",
    # Metadata
    "__version__",
    "__author__",
    "__email__",
]
