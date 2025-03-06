from http import HTTPStatus
from typing import Optional, Union
from typing_extensions import Self

import aiohttp
import asyncio

from anyrun.utils.config import Config
from anyrun.utils.exceptions import RunTimeException
from anyrun.utils.utility_functions import execute_synchronously, get_running_loop


class AnyRunConnector:

    def __init__(
            self,
            api_key: str,
            user_agent: str = Config.PUBLIC_USER_AGENT,
            trust_env: bool = False,
            verify_ssl: bool = False,
            proxy: Optional[str] = None,
            proxy_auth: Optional[str] = None,
            connector: Optional[aiohttp.BaseConnector] = None,
            timeout: int = Config.DEFAULT_REQUEST_TIMEOUT_IN_SECONDS,
    ) -> None:
        """
        :param api_key: ANY.RUN Feeds API Key in format: Basic <base64_auth>
        :param user_agent: User-Agent header value
        :param trust_env: Trust environment settings for proxy configuration
        :param verify_ssl: Perform SSL certificate validation for HTTPS requests
        :param proxy: Proxy url
        :param proxy_auth: Proxy authorization url
        :param connector: A custom aiohttp connector
        :param timeout: Override the session’s timeout
        """
        self._proxy = proxy
        self._proxy_auth = proxy_auth
        self._trust_env = trust_env
        self._connector = connector
        self._timeout = timeout
        self._verify_ssl = verify_ssl
        self._session: Optional[aiohttp.ClientSession] = None

        self._api_key_validator(api_key)
        self._setup_connector()
        self._setup_headers(api_key, user_agent)

    def __enter__(self) -> Self:
        execute_synchronously(self._open_session)
        return self

    def __exit__(self, item_type, value, traceback) -> None:
        execute_synchronously(self._close_session)

    async def __aenter__(self) -> Self:
        await self._open_session()
        return self

    async def __aexit__(self, item_type, value, traceback) -> None:
        await self._close_session()

    async def _make_request_async(
            self,
            method: str,
            url: str,
            json: Optional[dict] = None,
            data: Union[dict, aiohttp.MultipartWriter, None] = None,
            parse_response: bool = True
    ) -> Union[dict, aiohttp.ClientResponse]:
        """
        Provides async interface for making any request

        :param method: HTTP method
        :param url: Request url
        :param json: Request json
        :param data: Request data
        :param parse_response: Enable/disable API response parsing. If enabled, returns response.json() object dict
            else aiohttp.ClientResponse instance
        :return: Api response
        :raises RunTimeException: If the connector was executed outside the context manager
        """
        try:
            response: aiohttp.ClientResponse = await self._session.request(
                method,
                url,
                json=json,
                data=data
            )
        except AttributeError:
            raise RunTimeException(
                {
                    'status': 'error',
                    'description': 'The connector object must be executed using the context manager'
                }
            )

        if parse_response:
            response_data = await response.json()
            return await self._check_response_status(response_data, response.status)
        return response

    def _setup_connector(self) -> None:
        if not self._connector and self._verify_ssl:
            event_loop = get_running_loop()
            asyncio.set_event_loop(event_loop)
            self._connector = aiohttp.TCPConnector(ssl=self._verify_ssl, loop=event_loop)

    def _setup_headers(self, api_key: str, user_agent: str) -> None:
        self._headers = {
            'Authorization': api_key,
            'User-Agent': f'{user_agent}:{Config.SDK_USER_AGENT}'
        }

    async def _open_session(self) -> None:
        if not self._session:
            self._session = aiohttp.ClientSession(
                trust_env=self._trust_env,
                connector=self._connector,
                proxy=self._proxy,
                proxy_auth=self._proxy_auth,
                timeout=aiohttp.ClientTimeout(total=self._timeout),
                headers=self._headers
            )

    async def _close_session(self) -> None:
        if self._session:
            await self._session.close()
            self._session = None

    @staticmethod
    async def _check_response_status(response_data: dict, status: int) -> dict:
        """
        Process ANY.RUN endpoint response.

        Returns a dictionary with an explanation of the error if the response status code is not equal **OK**

        :param response_data: API response
        :return: The collection of IOCs
        :raises RunTimeException: If status code 200 is not received
        """
        if status in (HTTPStatus.OK, HTTPStatus.CREATED, HTTPStatus.ACCEPTED):
            return response_data

        raise RunTimeException(
            {
                'status': 'error',
                'code': response_data.get('code') or HTTPStatus.BAD_REQUEST,
                'description': response_data.get('message')
            }
        )

    @staticmethod
    def _api_key_validator(api_key: str) -> None:
        """
        Checks if API key format is valid

        :param api_key:
        :raises RunTimeException: If API key format is not valid
        """
        if not isinstance(api_key, str):
            raise RunTimeException(
                {
                    'status': 'error',
                    'description': 'The ANY.RUN api key must be a valid string'
                }
            )
