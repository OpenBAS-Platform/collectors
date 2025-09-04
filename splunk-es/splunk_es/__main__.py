"""
Main entry point for running the Splunk ES collector as a module.

This allows the collector to be run directly using:
    python -m splunk_es

Usage:
    python -m splunk_es
"""

from openaev_splunk_es import main

if __name__ == "__main__":
    exit(main())
