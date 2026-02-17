import os
from typing import Optional, Union
from typing_extensions import Self

import aiohttp
import requests

from anyrun.utils.config import Config
from anyrun.utils.utility_functions import execute_synchronously
from anyrun.connectors.base_connector import AnyRunConnector


class GenericEnvironment:
    def __init__(self, endpoint_url: str) -> None:
        """
        :param endpoint_url: The URL for the custom endpoint.
        """
        self._endpoint_url = endpoint_url

    def __enter__(self) -> Self:
        os.environ["ANYRUN_GENERIC_ENDPOINT_URL"] = self._endpoint_url
        print(
            f"[ANY.RUN] The SDK now uses a custom endpoint: {self._endpoint_url}.\n"
            f"The new endpoint URL is stored in an environment variable: 'ANYRUN_GENERIC_ENDPOINT_URL'."
        )
        return self

    def __exit__(self, item_type, value, traceback) -> None:
        os.environ.pop("ANYRUN_GENERIC_ENDPOINT_URL")
        print(f"[ANY.RUN] 'ANYRUN_GENERIC_ENDPOINT_URL' was deleted.")

    def generic_request(
        self,
        api_key: str,
        method: str,
        json: Optional[dict] = None,
        data: Union[dict, aiohttp.MultipartWriter, None] = None,
        files: Optional[dict[str, tuple[str, bytes]]] = None,
        parse_response: bool = True,
        request_timeout: Optional[int] = None,
        integration: str = Config.PUBLIC_INTEGRATION,
        trust_env: bool = False,
        verify_ssl: Optional[str] = None,
        proxy: Optional[str] = None,
        proxy_username: Optional[str] = None,
        proxy_password: Optional[str] = None,
        connector: Optional[aiohttp.BaseConnector] = None,
        timeout: int = Config.DEFAULT_REQUEST_TIMEOUT_IN_SECONDS,
        enable_requests: bool = False
    ) -> Union[dict, list[dict], aiohttp.ClientResponse, requests.Response]:
        """
        Provides sync interface for making any request

        :param api_key: ANY.RUN API-KEY in format: API-KEY <token> or Basic token in format: Basic <base64_auth>.
        :param method: HTTP method
        :param json: Request json
        :param data: Request data
        :param files: Request files (only for the requests package)
        :param parse_response: Enable/disable API response parsing. If enabled, returns response.json() object dict
            else aiohttp.ClientResponse instance
        :param request_timeout: HTTP Request timeout
        :return: Api response
        :raises RunTimeException: If the connector was executed outside the context manager
                :param integration: Name of the integration.
        :param trust_env: Trust environment settings for proxy configuration.
        :param verify_ssl: Enable/disable SSL verification option.
        :param proxy: Proxy url. Example: https://<host>:<port>.
        :param proxy_username: Proxy username.
        :param proxy_password: Proxy password.
        :param connector: A custom aiohttp connector.
        :param timeout: Override the session’s timeout.
        :param enable_requests: Use requests.request to make api calls. May block the event loop.
        """
        return execute_synchronously(
            self.generic_request_async,
            api_key,
            method,
            json,
            data,
            files,
            parse_response,
            request_timeout,
            integration,
            trust_env,
            verify_ssl,
            proxy,
            proxy_username,
            proxy_password,
            connector,
            timeout,
            enable_requests
        )

    async def generic_request_async(
        self,
        api_key: str,
        method: str,
        json: Optional[dict] = None,
        data: Union[dict, aiohttp.MultipartWriter, None] = None,
        files: Optional[dict[str, tuple[str, bytes]]] = None,
        parse_response: bool = True,
        request_timeout: Optional[int] = None,
        integration: str = Config.PUBLIC_INTEGRATION,
        trust_env: bool = False,
        verify_ssl: Optional[str] = None,
        proxy: Optional[str] = None,
        proxy_username: Optional[str] = None,
        proxy_password: Optional[str] = None,
        connector: Optional[aiohttp.BaseConnector] = None,
        timeout: int = Config.DEFAULT_REQUEST_TIMEOUT_IN_SECONDS,
        enable_requests: bool = False
    ) -> Union[dict, list[dict], aiohttp.ClientResponse, requests.Response]:
        """
        Provides async interface for making any request

        :param api_key: ANY.RUN API-KEY in format: API-KEY <token> or Basic token in format: Basic <base64_auth>.
        :param method: HTTP method
        :param json: Request json
        :param data: Request data
        :param files: Request files (only for the requests package)
        :param parse_response: Enable/disable API response parsing. If enabled, returns response.json() object dict
            else aiohttp.ClientResponse instance
        :param request_timeout: HTTP Request timeout
        :return: Api response
        :raises RunTimeException: If the connector was executed outside the context manager
                :param integration: Name of the integration.
        :param trust_env: Trust environment settings for proxy configuration.
        :param verify_ssl: Enable/disable SSL verification option.
        :param proxy: Proxy url. Example: https://<host>:<port>.
        :param proxy_username: Proxy username.
        :param proxy_password: Proxy password.
        :param connector: A custom aiohttp connector.
        :param timeout: Override the session’s timeout.
        :param enable_requests: Use requests.request to make api calls. May block the event loop.
        """
        async with AnyRunConnector(
            api_key,
            integration,
            trust_env,
            verify_ssl,
            proxy,
            proxy_username,
            proxy_password,
            connector,
            timeout,
            enable_requests
        ) as connector:
            response = await connector._make_request_async(
                method,
                self._endpoint_url,
                json,
                data,
                files,
                parse_response,
                request_timeout
            )

        return response
