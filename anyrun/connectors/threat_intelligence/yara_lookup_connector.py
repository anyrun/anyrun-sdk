from typing import Optional

import aiohttp
import asyncio

from anyrun.connectors.base_connector import AnyRunConnector
from anyrun.utils.config import Config
from anyrun.utils.utility_functions import execute_synchronously

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
        :param api_key: ANY.RUN Feeds API Key in format: API-KEY <api_key>
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

    def get_yara(
            self,
            yara_rule: str,
            stix: bool = False,
            ssl: bool = False
    ) -> list[Optional[dict]]:
        """
        Returns YARA search matches

        :param yara_rule: Valid YARA rule
        :param stix: Enable/disable receiving matches in stix format
        :param ssl: Enable/disable ssl verification
        :return: API response in specified format. Returns an empty list if no matches are found
        """
        return execute_synchronously(self.get_yara_async, yara_rule, stix, ssl)

    async def get_yara_async(
            self,
            yara_rule: str,
            stix: bool = False,
            ssl: bool = False
    ) -> list[Optional[dict]]:
        """
        Returns YARA search matches

        :param yara_rule: Valid YARA rule
        :param stix: Enable/disable receiving matches in stix format
        :param ssl: Enable/disable ssl verification
        :return: API response in specified format. Returns an empty list if no matches are found
        """
        search_id = await self._initialize_search_async(yara_rule, ssl)
        search_matches = await self._get_search_matches_async(search_id, ssl)

        if search_matches > 0:
            if stix:
                return await self._get_stix_search_result_async(search_id, ssl)
            return await self._get_search_result_async(search_id, ssl)
        return []

    async def _initialize_search_async(self, yara_rule: str, ssl: bool = False) -> str:
        """
        Executes initial request to yara-lookup and gets the search ID

        :param yara_rule: Valid YARA rule
        :param ssl: Enable/disable ssl verification
        :return: Search ID
        """
        url = f'{Config.ANY_RUN_API_URL}/intelligence/yara-lookup/search'
        body = {'query': yara_rule}

        response_data = await self.make_request_async('POST', url, ssl=ssl, json=body)
        return response_data.get('queryId')

    async def _get_search_matches_async(self, search_id: str, ssl: bool = False) -> int:
        """
        Gets the number of search matches

        :param search_id: Search ID
        :param ssl: Enable/disable ssl verification
        :return: Number of matches
        """
        url = f'{Config.ANY_RUN_API_URL}/intelligence/yara-lookup/search/{search_id}/count'

        response_data = await self._wait_for_search_complete('GET', url, ssl=ssl)
        return response_data.get('foundMatches')

    async def _wait_for_search_complete(self, method: str, url: str, ssl: bool = False) -> dict:
        """
        Makes request to get the matches count. If search is not completed, sleep for the specified time and
        repeats the request. Returns the number of search matches if search is complete

        :param method: HTTP method
        :param url: ANY.RUN yara-lookup endpoint url
        :param ssl: Enable/disable ssl verification
        :return: Number of matches
        """
        while True:
            response_data = await self.make_request_async(method, url, ssl=ssl)

            if response_data.get('searchInfo').get('status') == 'done':
                return response_data

            await asyncio.sleep(Config.DEFAULT_WAITING_TIMEOUT_IN_SECONDS)

    async def _get_search_result_async(self, search_id: str, ssl: bool = False) -> list[Optional[dict]]:
        """
        Returns YARA search matches in json format

        :param search_id: Search ID
        :param ssl: ssl: Enable/disable ssl verification
        :return: API response in specified format. Returns an empty list if no matches are found
        """
        url = f'{Config.ANY_RUN_API_URL}/intelligence/yara-lookup/search/{search_id}'

        response_data = await self.make_request_async('GET', url, ssl)
        return response_data.get('matches')

    async def _get_stix_search_result_async(self, search_id: str, ssl: bool = False) -> list[Optional[dict]]:
        """
        Returns YARA search matches in stix format

        :param search_id: Search ID
        :param ssl: ssl: Enable/disable ssl verification
        :return: API response in specified format. Returns an empty list if no matches are found
        """
        url = f'{Config.ANY_RUN_API_URL}/intelligence/yara-lookup/search/{search_id}/download/stix'

        response_data = await self.make_request_async('GET', url, ssl)
        return response_data.get('data').get('objects')
