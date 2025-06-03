from http import HTTPStatus
from typing import Optional, Union
from typing_extensions import Self
from abc import abstractmethod

import aiohttp
import asyncio
import requests

from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning

from anyrun.utils.config import Config
from anyrun.utils.exceptions import RunTimeException
from anyrun.utils.utility_functions import execute_synchronously, get_running_loop

disable_warnings(InsecureRequestWarning)

class AnyRunConnector:

    def __init__(
            self,
            api_key: str,
            integration: str = Config.PUBLIC_INTEGRATION,
            trust_env: bool = False,
            verify_ssl: Optional[str] = None,
            proxy: Optional[str] = None,
            connector: Optional[aiohttp.BaseConnector] = None,
            timeout: int = Config.DEFAULT_REQUEST_TIMEOUT_IN_SECONDS,
            enable_requests: bool = False
    ) -> None:
        """
        :param api_key: ANY.RUN Feeds API Key in format: Basic <base64_auth>
        :param integration: Name of the integration
        :param trust_env: Trust environment settings for proxy configuration
        :param verify_ssl: Path to SSL certificate
        :param proxy: Proxy url. Example: http://<user>:<pass>@<proxy>:<port>
        :param connector: A custom aiohttp connector
        :param timeout: Override the session’s timeout
        :param enable_requests: Use requests.request to make api calls. May block the event loop
        """
        self._proxy = proxy
        self._trust_env = trust_env
        self._connector = connector
        self._timeout = timeout
        self._enable_requests = enable_requests
        self._verify_ssl = verify_ssl
        self._session: Optional[aiohttp.ClientSession] = None

        self._api_key_validator(api_key)
        self._setup_connector()
        self._setup_headers(api_key, integration)

        self._taxii_delta_timestamp: Optional[str] = None

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

    def check_proxy(self) -> dict:
        """
        Executes test proxy request to google.com

        :returns: Verification status
        """
        return execute_synchronously(self.check_proxy_async)

    async def check_proxy_async(self) -> dict:
        """"
        Executes test proxy request to google.com

        :returns: Verification status
        """
        try:
            await self._make_request_async('GET', 'https://google.com')
        except (aiohttp.ClientError, requests.RequestException, OSError) as exception:
            raise RunTimeException(f'The proxy request failed. Check the proxy settings are correct') from exception
        return {'status': 'ok', 'description': 'Successful proxy verification'}

    async def _make_request_async(
            self,
            method: str,
            url: str,
            json: Optional[dict] = None,
            data: Union[dict, aiohttp.MultipartWriter, None] = None,
            parse_response: bool = True
    ) -> Union[dict, list[dict], aiohttp.ClientResponse]:
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
            if self._enable_requests:
                response: requests.Response = requests.request(
                    method,
                    url,
                    headers=self._headers,
                    json=json,
                    params=data,
                    verify=True if self._verify_ssl else False,
                    cert=self._verify_ssl,
                    proxies=self._generate_proxy_config() if self._proxy else None
                )
            else:
                response: aiohttp.ClientResponse = await self._session.request(
                    method,
                    url,
                    json=json,
                    data=data,
                    ssl=True if self._verify_ssl else False
                )
        except AttributeError:
            raise RunTimeException('The connector object must be executed using the context manager')

        self._update_taxii_delta_timestamp(response)

        if parse_response:
            response_data = response.json() if self._enable_requests else await response.json()
            return await self._check_response_status(
                response_data,
                response.status_code if self._enable_requests else response.status
            )
        return response

    def _setup_connector(self) -> None:
        if not self._connector and self._verify_ssl:
            event_loop = get_running_loop()
            asyncio.set_event_loop(event_loop)
            self._connector = aiohttp.TCPConnector(ssl=self._verify_ssl, loop=event_loop)

    def _setup_headers(self, api_key: str, integration: str) -> None:
        self._headers = {
            'Authorization': api_key,
            'x_anyrun_connector': integration,
            'x_anyrun_sdk': Config.SDK_VERSION
        }

    async def _open_session(self) -> None:
        if not self._session:
            self._session = aiohttp.ClientSession(
                trust_env=self._trust_env,
                connector=self._connector,
                proxy=self._proxy,
                timeout=aiohttp.ClientTimeout(total=self._timeout),
                headers=self._headers
            )

    async def _close_session(self) -> None:
        if self._session:
            await self._session.close()
            self._session = None

    def _generate_proxy_config(self) -> Optional[dict[str, str]]:
        """
        Generates proxies dict using received proxy string

        :return: Proxy dict
        """
        if self._proxy:
            if '@' in self._proxy:
                auth, connection = self._proxy[self._proxy.index('//') + 2:].split('@')
                user, password = auth.split(':')
                host, port = connection.split(':')

                return {
                    'http': f'http://{user}:{password}@{host}:{port}/',
                    'https': f'https://{user}:{password}@{host}:{port}/'
                }

            host, port = self._proxy[self._proxy.index('//') + 2:].split(':')
            return {
                'http': f'http://{host}:{port}/',
                'https': f'https://{host}:{port}/'
            }

    def _update_taxii_delta_timestamp(self, response: Union[aiohttp.ClientResponse, requests.Response]) -> None:
        """
        Updates taxii delta timestamp

        :param response: Response content
        """
        delta_timestamp = response.headers.get('X-TAXII-Date-Modified-Last')
        if delta_timestamp:
            self._taxii_delta_timestamp = delta_timestamp

    @abstractmethod
    def check_authorization(self) -> dict:
        """
        Makes a request to check the validity of the API key.
        The request does not consume the license

        :return: Verification status
        """
        pass

    @abstractmethod
    async def check_authorization_async(self) -> dict:
        """
        Makes a request to check the validity of the API key.
        The request does not consume the license

        :return: Verification status
        """
        pass

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

        raise RunTimeException(response_data.get('message'), status or HTTPStatus.BAD_REQUEST)

    @staticmethod
    def _api_key_validator(api_key: str) -> None:
        """
        Checks if API key format is valid

        :param api_key:
        :raises RunTimeException: If API key format is not valid
        """
        if not isinstance(api_key, str):
            raise RunTimeException('The ANY.RUN api key must be a valid string')
