import asyncio
import os
from abc import abstractmethod
from http import HTTPStatus
from typing import Any, Optional, Union
from warnings import warn

import aiohttp
import requests
from aiohttp import BasicAuth
from typing_extensions import Self

from anyrun.utils.config import Config
from anyrun.utils.exceptions import RunTimeException
from anyrun.utils.utility_functions import execute_synchronously, get_running_loop


class AnyRunConnector:
    def __init__(
        self,
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
    ) -> None:
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
        :param root_url: Root url.
        :param team_id: Teamspace team identifier. Applied to every request made by the connector.
        :param customer_id: Teamspace customer identifier. Applied to every request made by the connector.
        :param case_id: Teamspace case identifier. Used only by the Sandbox requests.
        """
        self._proxy = proxy
        self._proxy_username = proxy_username
        self._proxy_password = proxy_password
        self._trust_env = trust_env
        self._connector = connector
        self._timeout = timeout
        self._enable_requests = enable_requests
        self._verify_ssl = verify_ssl
        self._session: Optional[aiohttp.ClientSession] = None
        self._api_key: Optional[str] = None

        self._api_key_validator(api_key)
        self._setup_connector()
        self._setup_headers(integration)
        self._setup_teamspace_scope(team_id=team_id, case_id=case_id, customer_id=customer_id)

        self._response_headers: dict[str, Any] = dict()

        self.ANY_RUN_API_URL = Config.ANY_RUN_API_URL.format(root_url=root_url)
        self.ANY_RUN_CONTENT_URL = Config.ANY_RUN_CONTENT_URL.format(root_url=root_url)
        self.ANY_RUN_REPORT_URL = Config.ANY_RUN_REPORT_URL.format(root_url=root_url)
        self.ANY_RUN_APP_URL = Config.ANY_RUN_APP_URL.format(root_url=root_url)

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
        """
        "
        Executes test proxy request to google.com

        :returns: Verification status
        """
        try:
            await self._make_request_async(
                'GET', 'https://google.com', request_timeout=5, parse_response=False, scoped=False
            )
        except (aiohttp.ClientError, requests.RequestException, OSError) as exception:
            raise RunTimeException('The proxy request failed. Check the proxy settings are correct') from exception
        return {'status': 'ok', 'description': 'Successful proxy verification'}

    async def _make_request_async(
        self,
        method: str,
        url: str,
        json: Optional[dict] = None,
        data: Union[dict, aiohttp.MultipartWriter, None] = None,
        files: Optional[dict[str, tuple[str, bytes]]] = None,
        parse_response: bool = True,
        request_timeout: Optional[int] = None,
        params: Optional[dict] = None,
        stream: bool = False,
        scoped: bool = True,
    ) -> Union[dict, list[dict], aiohttp.ClientResponse, requests.Response]:
        """
        Provides async interface for making any request

        :param method: HTTP method
        :param url: Request url
        :param json: Request json
        :param data: Request data
        :param files: Request files (only for the requests package)
        :param parse_response: Enable/disable API response parsing. If enabled, returns response.json() object dict
            else aiohttp.ClientResponse instance
        :param request_timeout: HTTP Request timeout
        :param params: Request query parameters
        :param stream: Do not read the response body in advance (only for the requests package, aiohttp always streams)
        :param scoped: Attach the Teamspace scope to the request. POST requests receive it in the body,
            GET requests in the query parameters
        :return: Api response
        :raises RunTimeException: If the connector was executed outside the context manager
        """
        url = os.environ.get('ANYRUN_GENERIC_ENDPOINT_URL') or url

        if scoped:
            json, data, params = self._apply_teamspace_scope(method, json, data, files, params)

        try:
            if self._enable_requests:
                response: requests.Response = requests.request(
                    method,
                    url,
                    headers=self._headers,
                    json=json,
                    data=data if isinstance(data, dict) else None,
                    params=params,
                    files=files,
                    verify=self._verify_ssl,
                    proxies=self._generate_proxy_config() if self._proxy else None,
                    timeout=request_timeout,
                    stream=stream,
                )
            else:
                response: aiohttp.ClientResponse = await self._session.request(
                    method, url, json=json, data=data, ssl=True if self._verify_ssl else False, timeout=request_timeout, params=params
                )

            self._response_headers = response.headers

            if parse_response:
                response_data = response.json() if self._enable_requests else await response.json()
                return await self._check_response_status(response_data, response.status_code if self._enable_requests else response.status)
            return response

        except AttributeError:
            raise RunTimeException('The connector object must be executed using the context manager')
        except (aiohttp.ClientError, requests.RequestException, OSError) as exception:
            raise RunTimeException(f'Connection error: {exception}')
        except Exception as e:
            raise RunTimeException(f'Unknown error: {e}')

    def _setup_teamspace_scope(
        self,
        team_id: Optional[str] = None,
        case_id: Optional[str] = None,
        customer_id: Optional[str] = None,
    ) -> None:
        """
        Builds Teamspace scope parameters.
        Parameters that are not set are omitted so the server applies its own defaults.

        :param team_id: Teamspace team identifier.
        :param customer_id: Teamspace customer identifier.
        :param case_id: Teamspace case identifier.
        :return: None
        """
        self.teamspace_scope = {}

        if team_id is not None:
            self.teamspace_scope['teamId'] = team_id

        if customer_id is not None:
            self.teamspace_scope['customerId'] = customer_id

        if case_id is not None:
            self.teamspace_scope['caseId'] = case_id

    def _apply_teamspace_scope(
        self,
        method: str,
        json: Optional[dict],
        data: Union[dict, aiohttp.MultipartWriter, None],
        files: Optional[dict[str, tuple[str, bytes]]],
        params: Optional[dict],
    ) -> tuple[Optional[dict], Union[dict, aiohttp.MultipartWriter, None], Optional[dict]]:
        """
        Attaches the Teamspace scope to the request: to the body of POST requests (json, form-data or multipart)
        and to the query parameters of GET requests. Other HTTP methods are left untouched.

        :param method: HTTP method
        :param json: Request json
        :param data: Request data
        :param files: Request files (only for the requests package)
        :param params: Request query parameters
        :return: Request json, data and query parameters including the scope
        """
        if not self.teamspace_scope:
            return json, data, params

        if method == 'GET':
            return json, data, {**(params or {}), **self.teamspace_scope}

        if method != 'POST':
            return json, data, params

        if isinstance(data, aiohttp.MultipartWriter):
            for field, value in self.teamspace_scope.items():
                data.append(value).set_content_disposition('form-data', name=field)
        elif files:
            # The requests package ignores json if files are sent, so the fields are sent as form-data instead
            data = {
                **{field: value for field, value in (json or {}).items() if value or value in (True, False)},
                **(data or {}),
                **self.teamspace_scope,
            }
            json = None
        else:
            json = {**(json or {}), **self.teamspace_scope}

        return json, data, params

    def _setup_connector(self) -> None:
        if not self._connector and self._verify_ssl:
            event_loop = get_running_loop()
            asyncio.set_event_loop(event_loop)
            self._connector = aiohttp.TCPConnector(ssl=self._verify_ssl, loop=event_loop)

    def _setup_headers(self, integration: str) -> None:
        self._headers = {'Authorization': self._api_key, 'x-anyrun-connector': integration, 'x-anyrun-sdk': Config.SDK_VERSION}

    async def _open_session(self) -> None:
        if not self._session:
            self._session = aiohttp.ClientSession(
                trust_env=self._trust_env,
                connector=self._connector,
                proxy=self._proxy,
                auth=BasicAuth(self._proxy_username, self._proxy_password) if self._proxy_username else None,
                timeout=aiohttp.ClientTimeout(total=self._timeout),
                headers=self._headers,
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
            protocol = self._proxy.split(':')[0]

            if self._proxy_username and self._proxy_password:
                connection = self._proxy[self._proxy.index('//') + 2 :]
                return {protocol: f'{protocol}://{self._proxy_username}:{self._proxy_password}@{connection}'}

            return {protocol: self._proxy}

        return None

    @abstractmethod
    def check_authorization(self) -> dict:
        """
        Makes a request to check the validity of the API key.
        The request does not consume the license

        :return: Verification status
        """

    @abstractmethod
    async def check_authorization_async(self) -> dict:
        """
        Makes a request to check the validity of the API key.
        The request does not consume the license

        :return: Verification status
        """

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

        raise RunTimeException(response_data.get('message') or response_data.get('description'), status or HTTPStatus.BAD_REQUEST)

    def _api_key_validator(self, api_key: str) -> None:
        """
        Checks if API key format is valid

        :param api_key: ANY.RUN API-KEY without a prefix.
        :raises RunTimeException: If API key format is not valid
        """
        if not api_key:
            raise RunTimeException('The ANY.RUN API key can not be empty.')
        if not isinstance(api_key, str):
            raise RunTimeException('The ANY.RUN API key must be a valid string')
        if api_key.lower().startswith('api-key') or api_key.lower().startswith('basic'):
            warn(
                'To access all ANY.RUN services, please use an API key without a prefix. '
                'API keys with a prefix and access to TI Feeds via Basic Authentication are '
                'supported only for backward compatibility and will be removed in future releases.'
            )
        else:
            api_key = 'API-KEY ' + api_key

        self._api_key = api_key
