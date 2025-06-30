"""
OpenAEV Splunk ES Collector Entry Point.

This module provides the main entry point for the Splunk ES collector
running in a Docker container environment.
"""

from splunk_es.splunk_es_collector import SplunkESCollector


def main():
    """
    Main entry point for the Splunk ES collector.

    Creates and starts the collector daemon with default configuration.
    Designed to run in a containerized environment.
    """
    try:
        collector = SplunkESCollector()
        collector.start()
    except Exception as e:
        print(f"Collector failed to start: {e}")
        raise


if __name__ == "__main__":
    main()
