from typing import Optional

import aiohttp

from anyrun.utils.config import Config
from anyrun.connectors.sandbox.operation_systems import WindowsConnector, AndroidConnector, UbuntuConnector


class SandboxConnector:
    """ Connectors Factory. Creates a concrete connector instance according to the method called """
    @staticmethod
    def windows(
            api_key: str,
            user_agent: str = Config.PUBLIC_USER_AGENT,
            trust_env: bool = False,
            verify_ssl: bool = False,
            proxy: Optional[str] = None,
            proxy_auth: Optional[str] = None,
            connector: Optional[aiohttp.BaseConnector] = None,
            timeout: int = Config.DEFAULT_REQUEST_TIMEOUT_IN_SECONDS
    ) -> WindowsConnector:
        """
        :param api_key: ANY.RUN API Key in format: API-KEY <api_key> or Basic <base64_auth>
        :param user_agent: User-Agent header value
        :param trust_env: Trust environment settings for proxy configuration
        :param verify_ssl: Perform SSL certificate validation for HTTPS requests
        :param proxy: Proxy url
        :param proxy_auth: Proxy authorization url
        :param connector: A custom aiohttp connector
        :param timeout: Override the session’s timeout
        """

        return WindowsConnector(
            api_key=api_key,
            user_agent=user_agent,
            trust_env=trust_env,
            verify_ssl=verify_ssl,
            proxy=proxy,
            proxy_auth=proxy_auth,
            connector=connector,
            timeout=timeout
        )

    @staticmethod
    def ubuntu(
            api_key: str,
            user_agent: str = Config.PUBLIC_USER_AGENT,
            trust_env: bool = False,
            verify_ssl: bool = False,
            proxy: Optional[str] = None,
            proxy_auth: Optional[str] = None,
            connector: Optional[aiohttp.BaseConnector] = None,
            timeout: int = Config.DEFAULT_REQUEST_TIMEOUT_IN_SECONDS
    ) -> UbuntuConnector:
        """
        :param api_key: ANY.RUN API Key in format: API-KEY <api_key> or Basic <base64_auth>
        :param user_agent: User-Agent header value
        :param trust_env: Trust environment settings for proxy configuration
        :param verify_ssl: Perform SSL certificate validation for HTTPS requests
        :param proxy: Proxy url
        :param proxy_auth: Proxy authorization url
        :param connector: A custom aiohttp connector
        :param timeout: Override the session’s timeout
        """

        return UbuntuConnector(
            api_key=api_key,
            user_agent=user_agent,
            trust_env=trust_env,
            verify_ssl=verify_ssl,
            proxy=proxy,
            proxy_auth=proxy_auth,
            connector=connector,
            timeout=timeout
        )

    @staticmethod
    def android(
            api_key: str,
            user_agent: str = Config.PUBLIC_USER_AGENT,
            trust_env: bool = False,
            verify_ssl: bool = False,
            proxy: Optional[str] = None,
            proxy_auth: Optional[str] = None,
            connector: Optional[aiohttp.BaseConnector] = None,
            timeout: int = Config.DEFAULT_REQUEST_TIMEOUT_IN_SECONDS
    ) -> AndroidConnector:
        """
        :param api_key: ANY.RUN API Key in format: API-KEY <api_key> or Basic <base64_auth>
        :param user_agent: User-Agent header value
        :param trust_env: Trust environment settings for proxy configuration
        :param verify_ssl: Perform SSL certificate validation for HTTPS requests
        :param proxy: Proxy url
        :param proxy_auth: Proxy authorization url
        :param connector: A custom aiohttp connector
        :param timeout: Override the session’s timeout
        """

        return AndroidConnector(
            api_key=api_key,
            user_agent=user_agent,
            trust_env=trust_env,
            verify_ssl=verify_ssl,
            proxy=proxy,
            proxy_auth=proxy_auth,
            connector=connector,
            timeout=timeout
        )