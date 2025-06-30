"""Conftest file for Pytest fixtures."""

from typing import TYPE_CHECKING, Any
from unittest.mock import patch

from pytest import fixture

if TYPE_CHECKING:
    from os import _Environ


def mock_env_vars(os_environ: "_Environ[str]", wanted_env: dict[str, str]) -> Any:
    """Fixture to mock environment variables dynamically and clean up after."""
    mock_env = patch.dict(os_environ, wanted_env)
    mock_env.start()

    return mock_env

@fixture(autouse=True)
def mock_openbas_client() -> Any:
    """Fixture to mock OpenBAS calls and clean up after."""
    mock_urllib= patch("urllib3.connectionpool.HTTPConnectionPool.urlopen")
    mock_pyobas = patch("pyobas.client.OpenBAS.http_request")
    mock_daemon_setup = patch("pyobas.daemons.collector_daemon.CollectorDaemon._setup")

    mock_urllib.start()
    mock_pyobas.start()
    mock_daemon_setup.start()

    yield mock_urllib, mock_pyobas, mock_daemon_setup

    mock_urllib.stop()
    mock_pyobas.stop()
    mock_daemon_setup.stop()