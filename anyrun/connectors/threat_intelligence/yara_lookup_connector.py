from uuid import UUID
from typing import Optional, Iterator, AsyncIterator

import aiohttp
import asyncio

from anyrun.connectors.base_connector import AnyRunConnector
from anyrun.utils.config import Config
from anyrun.utils.utility_functions import execute_synchronously, execute_async_iterator

class YaraLookupConnector(AnyRunConnector):
    """
    Provides ANY.RUN TI Yara Lookup endpoints management.
    Uses aiohttp library for the asynchronous calls
    """
    def __init__(
            self,
            api_key: str,
            user_agent: str = Config.PUBLIC_USER_AGENT,
            trust_env: bool = False,
            verify_ssl: bool = False,
            proxy: Optional[str] = None,
            proxy_auth: Optional[str] = None,
            connector: Optional[aiohttp.BaseConnector] = None,
            timeout: int = Config.DEFAULT_REQUEST_TIMEOUT_IN_SECONDS
    ) -> None:
        """
        :param api_key: ANY.RUN API Key in format: API-KEY <api_key>
        :param user_agent: User-Agent header value
        :param trust_env: Trust environment settings for proxy configuration
        :param verify_ssl: Perform SSL certificate validation for HTTPS requests
        :param proxy: Proxy url
        :param proxy_auth: Proxy authorization url
        :param connector: A custom aiohttp connector
        :param timeout: Override the session’s timeout
        """
        super().__init__(
            api_key,
            user_agent,
            trust_env,
            verify_ssl,
            proxy,
            proxy_auth,
            connector,
            timeout
        )

    def run_yara_search(self, yara_rule: str) -> str:
        """
         Initializes a new search according to the specified YARA rule
`
        :param yara_rule: Valid YARA rule
        :return: Search ID
        """
        return execute_synchronously(self.run_yara_search_async, yara_rule)

    async def run_yara_search_async(self, yara_rule: str) -> UUID:
        """
        Initializes a new search according to the specified YARA rule
`
        :param yara_rule: Valid YARA rule
        :return: Search ID
        """
        url = f'{Config.ANY_RUN_API_URL}/intelligence/yara-lookup/search'
        body = {'query': yara_rule}

        response_data = await self._make_request_async('POST', url, json=body)
        return response_data.get('queryId')

    def get_search_status(self, search_uuid: UUID, simplify: bool = True) -> Iterator[dict]:
        """
        Returns a synchronous iterator to process the actual status until the task is completed.

        :param search_uuid: Search ID
        :param simplify: Returns a simplified dict with the current search status
        :return: Number of matches
        """

        return execute_async_iterator(self.get_search_status_async(search_uuid, simplify))

    async def get_search_status_async(self, search_uuid: UUID, simplify: bool = True) -> AsyncIterator[dict]:
        """
        Returns an asynchronous iterator to process the actual status until the task is completed.

        :param search_uuid: Search ID
        :param simplify: Returns a simplified dict with the current search status
        :return: Number of matches
        """
        url = f'{Config.ANY_RUN_API_URL}/intelligence/yara-lookup/search/{search_uuid}/count'

        while True:
            response_data = await self._make_request_async('GET', url)

            if response_data.get('searchInfo').get('status') == 'done':
                yield await self._prepare_response(response_data, simplify)
                break
            else:
                yield await self._prepare_response(response_data, simplify)

            await asyncio.sleep(Config.DEFAULT_WAITING_TIMEOUT_IN_SECONDS)

    def get_search_result(self, search_uuid: UUID, simplify: bool = False) -> Optional[list[dict]]:
        """
        Returns a list of YARA search matches

        :param search_uuid: Search ID
        :param simplify: Return None if no threats has been detected
        :return: API response in specified format. Returns an empty list if no matches are found
        """
        return execute_synchronously(self.get_search_result_async, search_uuid, simplify)

    async def get_search_result_async(self, search_uuid: UUID, simplify: bool = False) -> Optional[list[dict]]:
        """
        Returns a list of YARA search matches

        :param search_uuid: Search ID
        :param simplify: Return None if no threats has been detected
        :return: API response in specified format. Returns an empty list if no matches are found
        """
        url = f'{Config.ANY_RUN_API_URL}/intelligence/yara-lookup/search/{search_uuid}'

        response_data = await self._make_request_async('GET', url)
        matches = response_data.get('matches')

        if simplify and not matches:
            return
        return matches

    def get_stix_search_result(self, search_uuid: UUID, simplify: bool = False) -> Optional[list[dict]]:
        """
        Returns a list of YARA search matches in stix format

        :param search_uuid: Search ID
        :param simplify: Returns None if no threats has been detected
        :return: API response in specified format. Returns an empty list if no matches are found
        """
        return execute_synchronously(self.get_stix_search_result_async, search_uuid, simplify)

    async def get_stix_search_result_async(self, search_uuid: UUID, simplify: bool = False) -> Optional[list[dict]]:
        """
        Returns a list of YARA search matches in stix format

        :param search_uuid: Search ID
        :param simplify: Returns None if no threats has been detected
        :return: API response in specified format. Returns an empty list if no matches are found
        """
        url = f'{Config.ANY_RUN_API_URL}/intelligence/yara-lookup/search/{search_uuid}/download/stix'

        response_data = await self._make_request_async('GET', url)
        objects = response_data.get('data').get('objects')

        if simplify and not objects:
            return
        return objects

    def get_yara(self, yara_rule: str, stix: bool = False) -> list[Optional[dict]]:
        """
        Automate YARA search methods management. Returns a complete list of YARA search matches

        :param yara_rule: Valid YARA rule
        :param stix: Enable/disable receiving matches in stix format
        :return: API response in specified format. Returns an empty list if no matches are found
        """
        return execute_synchronously(self.get_yara_async, yara_rule, stix)

    async def get_yara_async(self, yara_rule: str, stix: bool = False) -> list[Optional[dict]]:
        """
        Automate YARA search methods management. Returns a complete list of YARA search matches

        :param yara_rule: Valid YARA rule
        :param stix: Enable/disable receiving matches in stix format
        :return: API response in specified format. Returns an empty list if no matches are found
        """
        search_uuid = await self.run_yara_search_async(yara_rule)

        # Wait for the search to complete
        async for _ in self.get_search_status_async(search_uuid):
             pass

        if stix:
            return await self.get_search_result_async(search_uuid)
        return await self.get_stix_search_result_async(search_uuid)

    async def _prepare_response(self, response: dict, simplify: bool) -> dict:
        """
        Simplifies response structure if **simplify** parameter is specified

        :param response: Response dict
        :param simplify: Returns a simplified dict with the remaining scan time and the current task status
        :return: Response dict
        """
        if simplify:
            return {
                'status': await self._resolve_task_status(response.get('searchInfo').get('status'))
            }
        return response

    @staticmethod
    async def _resolve_task_status(status: Optional[str]) -> Optional[str]:
        """ Converts status code string representation """
        if status:
            if status == 'new':
                return 'PREPARING'
            if status == 'processing':
                return 'RUNNING'
            if status == 'done':
                return 'COMPLETED'
            return 'FAILED'
