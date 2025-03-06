from typing import Optional, Union, Any

import aiohttp

from anyrun.connectors.base_connector import AnyRunConnector

from anyrun.utils.config import Config
from anyrun.utils.utility_functions import execute_synchronously


class FeedsConnector(AnyRunConnector):
    """
    Provides ANY.RUN TI Feeds endpoints management.
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
        :param api_key: ANY.RUN API Key in format: Basic <base64_auth>
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

    def get_stix(
            self,
            ip: bool = True,
            url: bool = True,
            domain: bool = True,
            file: bool = True,
            port: bool = True,
            show_revoked: bool = False,
            get_new_ioc: bool = False,
            period: Optional[str] = None,
            date_from: Optional[int] = None,
            date_to: Optional[int] = None,
            limit: int = 100,
            page: int = 1
    ) -> list[Optional[dict]]:
        """
        Returns a list of ANY.RUN Feeds stix objects according to the specified query parameters

        :param ip: Enable or disable the IP type from the feed
        :param url: Enable or disable the URL type from the feed
        :param domain: Enable or disable the Domain type from the feed
        :param file: Enable or disable the File type from the feed
        :param port: Enable or disable the Port type from the feed
        :param show_revoked: Enable or disable receiving revoked feeds in report
        :param get_new_ioc: Receive only updated IOCs since the last request
        :param period: Time period to receive IOCs. Supports: day, week, month
        :param date_from: Beginning of the time period for receiving IOCs in timestamp format
        :param date_to: Ending of the time period for receiving IOCs in timestamp format
        :param limit: Number of tasks on a page. Default, all IOCs are included
        :param page: Page number. The last page marker is a response with a single **identity** object
        :return: The list of feeds in **stix** format
        """
        return execute_synchronously(
            self.get_stix_async,
            ip,
            url,
            domain,
            file,
            port,
            show_revoked,
            get_new_ioc,
            period,
            date_from,
            date_to,
            limit,
            page
        )

    async def get_stix_async(
            self,
            ip: bool = True,
            url: bool = True,
            domain: bool = True,
            file: bool = True,
            port: bool = True,
            show_revoked: bool = False,
            get_new_ioc: bool = False,
            period: Optional[str] = None,
            date_from: Optional[int] = None,
            date_to: Optional[int] = None,
            limit: int = 100,
            page: int = 1
    ) -> list[Optional[dict]]:
        """
        Returns a list of ANY.RUN Feeds stix objects according to the specified query parameters

        :param ip: Enable or disable the IP type from the feed
        :param url: Enable or disable the URL type from the feed
        :param domain: Enable or disable the Domain type from the feed
        :param file: Enable or disable the File type from the feed
        :param port: Enable or disable the Port type from the feed
        :param show_revoked: Enable or disable receiving revoked feeds in report
        :param get_new_ioc: Receive only updated IOCs since the last request
        :param period: Time period to receive IOCs. Supports: day, week, month
        :param date_from: Beginning of the time period for receiving IOCs in timestamp format
        :param date_to: Ending of the time period for receiving IOCs in timestamp format
        :param limit: Number of tasks on a page. Default, all IOCs are included
        :param page: Page number. The last page marker is a response with a single **identity** object
        :return: The list of feeds in **stix** format
        """
        url = await self._generate_feeds_url(
            'stix',
            {
                'IP': ip,
                'URL': url,
                'Domain': domain,
                'File': file,
                'Port': port,
                'showRevoked': show_revoked,
                'GetNewIoc': get_new_ioc,
                'period': period,
                'from': date_from,
                'to': date_to,
                'limit': limit,
                'page': page
             }
        )

        response_data = await self._make_request_async('GET', url)
        return response_data.get('data').get('objects')


    def get_misp(
            self,
            ip: bool = True,
            url: bool = True,
            domain: bool = True,
            show_revoked: bool = False,
            get_new_ioc: bool = False,
            period: Optional[str] = None,
            date_from: Optional[int] = None,
            date_to: Optional[int] = None,
            limit: int = 100,
            page: int = 1
    ) -> list[Optional[dict]]:
        """
        Returns a list of ANY.RUN Feeds misp objects according to the specified query parameters

        :param ip: Enable or disable the IP type from the feed
        :param url: Enable or disable the URL type from the feed
        :param domain: Enable or disable the Domain type from the feed
        :param show_revoked: Enable or disable receiving revoked feeds in report
        :param get_new_ioc: Receive only updated IOCs since the last request
        :param period: Time period to receive IOCs. Supports: day, week, month
        :param date_from: Beginning of the time period for receiving IOCs in timestamp format
        :param date_to: Ending of the time period for receiving IOCs in timestamp format
        :param limit: Number of tasks on a page. Default, all IOCs are included
        :param page: Page number. The last page marker is a response with a single **identity** object
        :return: The list of feeds in **misp** format
        """
        return execute_synchronously(
            self.get_misp_async,
            ip,
            url,
            domain,
            show_revoked,
            get_new_ioc,
            period,
            date_from,
            date_to,
            limit,
            page
        )

    async def get_misp_async(
            self,
            ip: bool = True,
            url: bool = True,
            domain: bool = True,
            show_revoked: bool = False,
            get_new_ioc: bool = False,
            period: Optional[str] = None,
            date_from: Optional[int] = None,
            date_to: Optional[int] = None,
            limit: int = 100,
            page: int = 1
    ) -> list[Optional[dict]]:
        """
        Returns a list of ANY.RUN Feeds misp objects according to the specified query parameters

        :param ip: Enable or disable the IP type from the feed
        :param url: Enable or disable the URL type from the feed
        :param domain: Enable or disable the Domain type from the feed
        :param show_revoked: Enable or disable receiving revoked feeds in report
        :param get_new_ioc: Receive only updated IOCs since the last request
        :param period: Time period to receive IOCs. Supports: day, week, month
        :param date_from: Beginning of the time period for receiving IOCs in timestamp format
        :param date_to: Ending of the time period for receiving IOCs in timestamp format
        :param limit: Number of tasks on a page. Default, all IOCs are included
        :param page: Page number. The last page marker is a response with a single **identity** object
        :return: The list of feeds in **misp** format
        """
        url = await self._generate_feeds_url(
            'misp',
            {
                'IP': ip,
                'URL': url,
                'Domain': domain,
                'showRevoked': show_revoked,
                'GetNewIoc': get_new_ioc,
                'period': period,
                'from': date_from,
                'to': date_to,
                'limit': limit,
                'page': page
            }
        )
        
        response_data = await self._make_request_async('GET', url)
        return response_data.get('data')

    def get_network_iocs(
            self,
            ip: bool = True,
            url: bool = True,
            domain: bool = True,
            show_revoked: bool = False,
            get_new_ioc: bool = False,
            period: Optional[str] = None,
            date_from: Optional[int] = None,
            date_to: Optional[int] = None,
            limit: int = 100,
            page: int = 1
    ) -> list[Optional[dict]]:
        """
        Returns a list of ANY.RUN Feeds network iocs objects according to the specified query parameters

        :param ip: Enable or disable the IP type from the feed
        :param url: Enable or disable the URL type from the feed
        :param domain: Enable or disable the Domain type from the feed
        :param show_revoked: Enable or disable receiving revoked feeds in report
        :param get_new_ioc: Receive only updated IOCs since the last request
        :param period: Time period to receive IOCs. Supports: day, week, month
        :param date_from: Beginning of the time period for receiving IOCs in timestamp format
        :param date_to: Ending of the time period for receiving IOCs in timestamp format
        :param limit: Number of tasks on a page. Default, all IOCs are included
        :param page: Page number. The last page marker is a response with a single **identity** object
        :return: The list of feeds in **network_iocs** format
        """
        return execute_synchronously(
            self.get_network_iocs_async,
            ip,
            url,
            domain,
            show_revoked,
            get_new_ioc,
            period,
            date_from,
            date_to,
            limit,
            page
        )

    async def get_network_iocs_async(
            self,
            ip: bool = True,
            url: bool = True,
            domain: bool = True,
            show_revoked: bool = False,
            get_new_ioc: bool = False,
            period: Optional[str] = None,
            date_from: Optional[int] = None,
            date_to: Optional[int] = None,
            limit: int = 100,
            page: int = 1
    ) -> list[Optional[dict]]:
        """
        Returns a list of ANY.RUN Feeds network iocs objects according to the specified query parameters

        :param ip: Enable or disable the IP type from the feed
        :param url: Enable or disable the URL type from the feed
        :param domain: Enable or disable the Domain type from the feed
        :param show_revoked: Enable or disable receiving revoked feeds in report
        :param get_new_ioc: Receive only updated IOCs since the last request
        :param period: Time period to receive IOCs. Supports: day, week, month
        :param date_from: Beginning of the time period for receiving IOCs in timestamp format
        :param date_to: Ending of the time period for receiving IOCs in timestamp format
        :param limit: Number of tasks on a page. Default, all IOCs are included
        :param page: Page number. The last page marker is a response with a single **identity** object
        :return: The list of feeds in **network_iocs** format
        """
        url = await self._generate_feeds_url(
            'network_iocs',
            {
                'IP': ip,
                'URL': url,
                'Domain': domain,
                'showRevoked': show_revoked,
                'GetNewIoc': get_new_ioc,
                'period': period,
                'from': date_from,
                'to': date_to,
                'limit': limit,
                'page': page
            }
        )

        response_data = await self._make_request_async('GET', url)
        return response_data.get('data')

    async def _generate_feeds_url(self, feed_format: str, params: dict) -> str:
        """
        Builds complete request url according to specified parameters

        :param feed_format: Supports: stix, misp, network_iocs
        :param params: Dictionary with query parameters
        :return: Complete url
        """
        url = f'{Config.ANY_RUN_API_URL}/feeds/{feed_format}.json?'
        query_params = '&'.join(
            [
                f'{param}={await self._parse_boolean(value)}'
                for param, value in params.items() if value
            ]
        )
        return url + query_params

    @staticmethod
    async def _parse_boolean(param: Any) -> Union[str, Any]:
        """ Converts a boolean value to a lowercase string """
        return str(param).lower() if str(param) in ("True", "False") else param
