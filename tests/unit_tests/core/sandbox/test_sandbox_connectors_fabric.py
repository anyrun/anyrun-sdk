"""Unit tests for anyrun.connectors.sandbox.sandbox_connectors_fabric."""

import pytest

from anyrun.connectors import SandboxConnector
from anyrun.connectors.sandbox.operation_systems import (
    WindowsConnector,
    LinuxConnector,
    AndroidConnector,
    MacOSConnector,
)


def test_sandbox_connector_windows_returns_windows_connector():
    connector = SandboxConnector.windows('mock_api_key')
    assert isinstance(connector, WindowsConnector)


def test_sandbox_connector_linux_returns_linux_connector():
    connector = SandboxConnector.linux('mock_api_key')
    assert isinstance(connector, LinuxConnector)


def test_sandbox_connector_android_returns_android_connector():
    connector = SandboxConnector.android('mock_api_key')
    assert isinstance(connector, AndroidConnector)


def test_sandbox_connector_macos_returns_macos_connector():
    connector = SandboxConnector.macos('mock_api_key')
    assert isinstance(connector, MacOSConnector)
