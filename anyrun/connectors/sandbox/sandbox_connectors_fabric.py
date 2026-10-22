from typing import Optional

import aiohttp

from anyrun.connectors.sandbox.operation_systems import AndroidConnector, LinuxConnector, MacOSConnector, WindowsConnector
from anyrun.utils.config import Config


class SandboxConnector:
    """Connectors Factory. Creates a concrete connector instance according to the method called"""

    @staticmethod
    def windows(
        api_key: str,
        integration: str = Config.PUBLIC_INTEGRATION,
        trust_env: bool = False,
        verify_ssl: Optional[str] = None,
        proxy: Optional[str] = None,
        proxy_username: Optional[str] = None,
        proxy_password: Optional[str] = None,
        connector: Optional[aiohttp.BaseConnector] = None,
        timeout: int = Config.DEFAULT_REQUEST_TIMEOUT_IN_SECONDS,
        enable_requests: bool = False,
        root_url: Optional[str] = Config.DEFAULT_ROOT_URL,
        team_id: Optional[str] = None,
        customer_id: Optional[str] = None,
        case_id: Optional[str] = None,
    ) -> WindowsConnector:
        """
        :param api_key: ANY.RUN API-KEY without a prefix.
        :param integration: Name of the integration.
        :param trust_env: Trust environment settings for proxy configuration.
        :param verify_ssl: Enable/disable SSL verification option.
        :param proxy: Proxy url. Example: http://<host>:<port>.
        :param proxy_username: Proxy username.
        :param proxy_password: Proxy password.
        :param connector: A custom aiohttp connector.
        :param timeout: Override the session’s timeout.
        :param enable_requests: Use requests.request to make api calls. May block the event loop.
        :param root_url: Root url.
        :param team_id: Teamspace team identifier. Applied to every request made by the connector.
        :param customer_id: Teamspace customer identifier. Applied to every request made by the connector.
        :param case_id: Teamspace case identifier. Used only by the Sandbox requests.
        """
        return WindowsConnector(
            api_key=api_key,
            integration=integration,
            trust_env=trust_env,
            verify_ssl=verify_ssl,
            proxy=proxy,
            proxy_username=proxy_username,
            proxy_password=proxy_password,
            connector=connector,
            timeout=timeout,
            enable_requests=enable_requests,
            root_url=root_url,
            team_id=team_id,
            customer_id=customer_id,
            case_id=case_id,
        )

    @staticmethod
    def linux(
        api_key: str,
        integration: str = Config.PUBLIC_INTEGRATION,
        trust_env: bool = False,
        verify_ssl: Optional[str] = None,
        proxy: Optional[str] = None,
        proxy_username: Optional[str] = None,
        proxy_password: Optional[str] = None,
        connector: Optional[aiohttp.BaseConnector] = None,
        timeout: int = Config.DEFAULT_REQUEST_TIMEOUT_IN_SECONDS,
        enable_requests: bool = False,
        root_url: Optional[str] = Config.DEFAULT_ROOT_URL,
        team_id: Optional[str] = None,
        customer_id: Optional[str] = None,
        case_id: Optional[str] = None,
    ) -> LinuxConnector:
        """
        :param api_key: ANY.RUN API-KEY without a prefix.
        :param integration: Name of the integration.
        :param trust_env: Trust environment settings for proxy configuration.
        :param verify_ssl: Enable/disable SSL verification option.
        :param proxy: Proxy url. Example: https://<host>:<port>.
        :param proxy_username: Proxy username.
        :param proxy_password: Proxy password.
        :param connector: A custom aiohttp connector.
        :param timeout: Override the session’s timeout.
        :param enable_requests: Use requests.request to make api calls. May block the event loop.
        :param root_url: Root URL for the API.
        :param team_id: Teamspace team identifier. Applied to every request made by the connector.
        :param customer_id: Teamspace customer identifier. Applied to every request made by the connector.
        :param case_id: Teamspace case identifier. Used only by the Sandbox requests.
        """
        return LinuxConnector(
            api_key=api_key,
            integration=integration,
            trust_env=trust_env,
            verify_ssl=verify_ssl,
            proxy=proxy,
            proxy_username=proxy_username,
            proxy_password=proxy_password,
            connector=connector,
            timeout=timeout,
            enable_requests=enable_requests,
            root_url=root_url,
            team_id=team_id,
            customer_id=customer_id,
            case_id=case_id,
        )

    @staticmethod
    def android(
        api_key: str,
        integration: str = Config.PUBLIC_INTEGRATION,
        trust_env: bool = False,
        verify_ssl: Optional[str] = None,
        proxy: Optional[str] = None,
        proxy_username: Optional[str] = None,
        proxy_password: Optional[str] = None,
        connector: Optional[aiohttp.BaseConnector] = None,
        timeout: int = Config.DEFAULT_REQUEST_TIMEOUT_IN_SECONDS,
        enable_requests: bool = False,
        root_url: Optional[str] = Config.DEFAULT_ROOT_URL,
        team_id: Optional[str] = None,
        customer_id: Optional[str] = None,
        case_id: Optional[str] = None,
    ) -> AndroidConnector:
        """
        :param api_key: ANY.RUN API-KEY without a prefix.
        :param integration: Name of the integration.
        :param trust_env: Trust environment settings for proxy configuration.
        :param verify_ssl: Enable/disable SSL verification option.
        :param proxy: Proxy url. Example: http://<host>:<port>.
        :param proxy_username: Proxy username.
        :param proxy_password: Proxy password.
        :param connector: A custom aiohttp connector.
        :param timeout: Override the session’s timeout.
        :param enable_requests: Use requests.request to make api calls. May block the event loop.
        :param root_url: Root URL for the API.
        :param team_id: Teamspace team identifier. Applied to every request made by the connector.
        :param customer_id: Teamspace customer identifier. Applied to every request made by the connector.
        :param case_id: Teamspace case identifier. Used only by the Sandbox requests.
        """
        return AndroidConnector(
            api_key=api_key,
            integration=integration,
            trust_env=trust_env,
            verify_ssl=verify_ssl,
            proxy=proxy,
            proxy_username=proxy_username,
            proxy_password=proxy_password,
            connector=connector,
            timeout=timeout,
            enable_requests=enable_requests,
            root_url=root_url,
            team_id=team_id,
            customer_id=customer_id,
            case_id=case_id,
        )

    @staticmethod
    def macos(
        api_key: str,
        integration: str = Config.PUBLIC_INTEGRATION,
        trust_env: bool = False,
        verify_ssl: Optional[str] = None,
        proxy: Optional[str] = None,
        proxy_username: Optional[str] = None,
        proxy_password: Optional[str] = None,
        connector: Optional[aiohttp.BaseConnector] = None,
        timeout: int = Config.DEFAULT_REQUEST_TIMEOUT_IN_SECONDS,
        enable_requests: bool = False,
        root_url: Optional[str] = Config.DEFAULT_ROOT_URL,
        team_id: Optional[str] = None,
        customer_id: Optional[str] = None,
        case_id: Optional[str] = None,
    ) -> MacOSConnector:
        """
        :param api_key: ANY.RUN API-KEY without a prefix.
        :param integration: Name of the integration.
        :param trust_env: Trust environment settings for proxy configuration.
        :param verify_ssl: Enable/disable SSL verification option.
        :param proxy: Proxy url. Example: https://<host>:<port>.
        :param proxy_username: Proxy username.
        :param proxy_password: Proxy password.
        :param connector: A custom aiohttp connector.
        :param timeout: Override the session’s timeout.
        :param enable_requests: Use requests.request to make api calls. May block the event loop.
        :param root_url: Root URL for the API.
        :param team_id: Teamspace team identifier. Applied to every request made by the connector.
        :param customer_id: Teamspace customer identifier. Applied to every request made by the connector.
        :param case_id: Teamspace case identifier. Used only by the Sandbox requests.
        """
        return MacOSConnector(
            api_key=api_key,
            integration=integration,
            trust_env=trust_env,
            verify_ssl=verify_ssl,
            proxy=proxy,
            proxy_username=proxy_username,
            proxy_password=proxy_password,
            connector=connector,
            timeout=timeout,
            enable_requests=enable_requests,
            root_url=root_url,
            team_id=team_id,
            customer_id=customer_id,
            case_id=case_id,
        )
