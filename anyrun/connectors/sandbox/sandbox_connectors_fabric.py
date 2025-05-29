from typing import Optional

import aiohttp

from anyrun.utils.config import Config
from anyrun.connectors.sandbox.operation_systems import WindowsConnector, AndroidConnector, LinuxConnector


class SandboxConnector:
    """ Connectors Factory. Creates a concrete connector instance according to the method called """
    @staticmethod
    def windows(
            api_key: str,
            integration: str = Config.PUBLIC_INTEGRATION,
            trust_env: bool = False,
            verify_ssl: Optional[str] = None,
            proxy: Optional[str] = None,
            connector: Optional[aiohttp.BaseConnector] = None,
            timeout: int = Config.DEFAULT_REQUEST_TIMEOUT_IN_SECONDS,
            enable_requests: bool = False
    ) -> WindowsConnector:
        """
        :param api_key: ANY.RUN API Key in format: API-KEY <api_key> or Basic <base64_auth>
        :param integration: Name of the integration
        :param trust_env: Trust environment settings for proxy configuration
        :param verify_ssl: Path to SSL certificate
        :param proxy: Proxy url. Example: http://<user>:<pass>@<proxy>:<port>
        :param connector: A custom aiohttp connector
        :param timeout: Override the session’s timeout
        :param enable_requests: Use requests.request to make api calls. May block the event loop
        """
        return WindowsConnector(
            api_key=api_key,
            integration=integration,
            trust_env=trust_env,
            verify_ssl=verify_ssl,
            proxy=proxy,
            connector=connector,
            timeout=timeout,
            enable_requests=enable_requests
        )

    @staticmethod
    def linux(
            api_key: str,
            integration: str = Config.PUBLIC_INTEGRATION,
            trust_env: bool = False,
            verify_ssl: Optional[str] = None,
            proxy: Optional[str] = None,
            connector: Optional[aiohttp.BaseConnector] = None,
            timeout: int = Config.DEFAULT_REQUEST_TIMEOUT_IN_SECONDS,
            enable_requests: bool = False
    ) -> LinuxConnector:
        """
        :param api_key: ANY.RUN API Key in format: API-KEY <api_key> or Basic <base64_auth>
        :param integration: Name of the integration
        :param trust_env: Trust environment settings for proxy configuration
        :param verify_ssl: Perform SSL certificate validation for HTTPS requests
        :param proxy: Proxy url. Example: http://<user>:<pass>@<proxy>:<port>
        :param connector: A custom aiohttp connector
        :param timeout: Override the session’s timeout
        :param enable_requests: Use requests.request to make api calls. May block the event loop
        """
        return LinuxConnector(
            api_key=api_key,
            integration=integration,
            trust_env=trust_env,
            verify_ssl=verify_ssl,
            proxy=proxy,
            connector=connector,
            timeout=timeout,
            enable_requests=enable_requests
        )

    @staticmethod
    def android(
            api_key: str,
            integration: str = Config.PUBLIC_INTEGRATION,
            trust_env: bool = False,
            verify_ssl: Optional[str] = None,
            proxy: Optional[str] = None,
            connector: Optional[aiohttp.BaseConnector] = None,
            timeout: int = Config.DEFAULT_REQUEST_TIMEOUT_IN_SECONDS,
            enable_requests: bool = False
    ) -> AndroidConnector:
        """
        :param api_key: ANY.RUN API Key in format: API-KEY <api_key> or Basic <base64_auth>
        :param integration: Name of the integration
        :param trust_env: Trust environment settings for proxy configuration
        :param verify_ssl: Perform SSL certificate validation for HTTPS requests
        :param proxy: Proxy url. Example: http://<user>:<pass>@<proxy>:<port>
        :param connector: A custom aiohttp connector
        :param timeout: Override the session’s timeout
        :param enable_requests: Use requests.request to make api calls. May block the event loop
        """
        return AndroidConnector(
            api_key=api_key,
            integration=integration,
            trust_env=trust_env,
            verify_ssl=verify_ssl,
            proxy=proxy,
            connector=connector,
            timeout=timeout,
            enable_requests=enable_requests
        )
