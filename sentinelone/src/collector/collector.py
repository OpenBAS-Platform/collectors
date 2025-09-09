"""Core collector."""

import os

from pyobas.daemons import CollectorDaemon  # type: ignore[import-untyped]
from src.services.utils import SentinelOneConfig

from .exception import (
    CollectorConfigError,
    CollectorProcessingError,
    CollectorSetupError,
)

LOG_PREFIX = "[Collector]"


class Collector(CollectorDaemon):  # type: ignore[misc]
    """Generic Collector using service provider pattern.

    This collector is use-case agnostic and works with any service provider.
    """

    def __init__(self) -> None:
        """Initialize the collector.

        Raises:
            CollectorConfigError: If collector initialization fails.

        """
        try:
            self.config = SentinelOneConfig()
            self.config_instance = self.config.load

            super().__init__(
                configuration=self.config_instance.to_daemon_config(),
                callback=self._process_callback,
            )

            self.logger.info(  # type: ignore[has-type]
                f"{LOG_PREFIX} SentinelOne Collector initialized successfully"
            )

        except Exception as err:
            import logging

            logging.basicConfig(level=logging.ERROR)
            self.logger = logging.getLogger(__name__)
            self.logger.error(f"{LOG_PREFIX} Failed to initialize collector: {err}")
            raise CollectorConfigError(
                f"Failed to initialize the collector: {err}"
            ) from err

    def _setup(self) -> None:
        """Set up the collector.

        Initializes SentinelOne services, expectation handler, expectation manager,
        and OpenBAS detection helper. Sets up the collector for processing expectations.

        Raises:
            CollectorSetupError: If collector setup fails.

        """
        try:
            self.logger.info(f"{LOG_PREFIX} Starting collector setup...")

            super()._setup()

            self.logger.debug(f"{LOG_PREFIX} Initializing SentinelOne services...")

        except Exception as err:
            self.logger.error(f"{LOG_PREFIX} Collector setup failed: {err}")
            raise CollectorSetupError(f"Failed to setup the collector: {err}") from err

    def _process_callback(self) -> None:
        """Process the callback for expectation processing.

        Executes a single processing cycle, handling expectations through the
        expectation manager and logging results. Handles keyboard interrupts
        and system exits gracefully.

        Raises:
            CollectorProcessingError: If processing cycle fails.

        """
        try:
            self.logger.info(f"{LOG_PREFIX} Starting processing cycle...")
            self.logger.debug(
                f"{LOG_PREFIX} Processing expectations using SentinelOne services"
            )

        except (KeyboardInterrupt, SystemExit):
            self.logger.info(f"{LOG_PREFIX} Collector stopping...")
            os._exit(0)
        except Exception as e:
            self.logger.error(f"{LOG_PREFIX} Error during processing cycle: {str(e)}")
            raise CollectorProcessingError(f"Processing error: {str(e)}") from e
