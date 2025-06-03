from typing import Optional, Union, Any

import aiohttp

from anyrun import RunTimeException
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
            integration: str = Config.PUBLIC_INTEGRATION,
            trust_env: bool = False,
            verify_ssl: Optional[str] = None,
            proxy: Optional[str] = None,
            connector: Optional[aiohttp.BaseConnector] = None,
            timeout: int = Config.DEFAULT_REQUEST_TIMEOUT_IN_SECONDS,
            enable_requests: bool = False
    ) -> None:
        """
        :param api_key: ANY.RUN API Key in format: Basic <base64_auth>
        :param integration: Name of the integration
        :param trust_env: Trust environment settings for proxy configuration
        :param verify_ssl: Path to SSL certificate
        :param proxy: Proxy url. Example: http://<user>:<pass>@<proxy>:<port>
        :param connector: A custom aiohttp connector
        :param timeout: Override the session’s timeout
        :param enable_requests: Use requests.request to make api calls. May block the event loop
        """
        super().__init__(
            api_key,
            integration,
            trust_env,
            verify_ssl,
            proxy,
            connector,
            timeout,
            enable_requests
        )

    def check_authorization(self) -> dict:
        """
        Makes a request to check the validity of the API key.
        The request does not consume the license

        return: Verification status
        """
        return execute_synchronously(self.check_authorization_async)

    async def check_authorization_async(self) -> dict:
        """
        Makes a request to check the validity of the API key.
        The request does not consume the license

        return: Verification status
        """
        await self.get_taxii_stix_async()
        return {'status': 'ok', 'description': 'Successful credential verification'}


    def get_taxii_stix(
            self,
            collection: str = 'full',
            match_type: Optional[str] = None,
            match_id: Optional[str] = None,
            match_revoked: bool = False,
            match_version: str = 'last',
            added_after: Optional[str] = None,
            modified_after: Optional[str] = None,
            limit: int = 100,
            next_page: Optional[str] = None,
            get_delta: bool = False
    ) -> dict:
        """
        Returns a list of ANY.RUN Feeds TAXII stix objects according to the specified query parameters

        :param collection: Collection type. Supports: full, ip, url, domain.
        :param match_type: Filter results based on the STIX object types.
        :param match_id: IOC identifier.
        :param match_revoked: Enable or disable receiving revoked feeds in report.
        :param match_version: Filter STIX objects by their object version.
        :param added_after: Receive IOCs after specified date.
        :param modified_after: Receive IOCs after specified date. Example: 2025-04-15.
        :param limit: Number of tasks on a page. Default, all IOCs are included.
        :param next_page: Page identifier.
        :param get_delta: Get only indicators modified since the last request. Works starting from the second request
        :return: The list of feeds in **stix** format
        """
        return execute_synchronously(
            self.get_taxii_stix_async,
            collection,
            match_type,
            match_id,
            match_revoked,
            match_version,
            added_after,
            modified_after,
            limit,
            next_page,
            get_delta
        )

    async def get_taxii_stix_async(
            self,
            collection: str = 'full',
            match_type: Optional[str] = None,
            match_id: Optional[str] = None,
            match_revoked: bool = False,
            match_version: str = 'last',
            added_after: Optional[str] = None,
            modified_after: Optional[str] = None,
            limit: int = 100,
            next_page: Optional[str] = None,
            get_delta: bool = False
    ) -> dict:
        """
        Returns a list of ANY.RUN Feeds TAXII stix objects according to the specified query parameters

        :param collection: Collection type. Supports: full, ip, url, domain.
        :param match_type: Filter results based on the STIX object types. You can enter multiple values
            separated by commas
        :param match_id: IOC identifier.
        :param match_version: Filter STIX objects by their object version.
        :param match_revoked: Enable or disable receiving revoked feeds in report.
        :param added_after: Receive IOCs after specified date. Example: 2025-04-15.
        :param modified_after: Receive IOCs after specified date. Example: 2025-04-15.
        :param limit: Number of tasks on a page. Default, all IOCs are included.
        :param next_page: Page identifier.
        :param get_delta: Get only indicators modified since the last request. Works starting from the second request
        :return: The list of feeds in **stix** format
        """
        collection_id = await self._get_collection_id(collection)

        if get_delta and self._taxii_delta_timestamp:
            modified_after = self._taxii_delta_timestamp

        url = await self._generate_feeds_url(
            f'{Config.ANY_RUN_API_URL}/feeds/taxii2/api1/collections/{collection_id}/objects/?',
            {
                'match[type]': match_type,
                'match[id]': match_id,
                'match[version]': match_version,
                'match[spec_version]': '2.1',
                'match[revoked]': match_revoked,
                'added_after': added_after,
                'modified_after': modified_after,
                'limit': limit,
                'next': next_page
             }
        )

        response_data = await self._make_request_async('GET', url)
        return response_data

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
        DEPRECATED: please, use get_taxii_stix instead

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
        DEPRECATED: please, use get_taxii_stix_async instead

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
            f'{Config.ANY_RUN_API_URL}/feeds/stix.json?',
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
            f'{Config.ANY_RUN_API_URL}/feeds/misp.json?',
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
            f'{Config.ANY_RUN_API_URL}/feeds/network_iocs.json?',
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

    async def _generate_feeds_url(self, url: str, params: dict) -> str:
        """
        Builds complete request url according to specified parameters

        :param url: Feeds endpoint url
        :param params: Dictionary with query parameters
        :return: Complete url
        """
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

    @staticmethod
    async def _get_collection_id(collection_name: str) -> str:
        """
        Converts TAXII collection name to collection identifier

        :param collection_name: TAXII collection name
        :return: TAXII collection identifier
        :raises RunTimeException: If invalid TAXII collection name is specified
        """
        if collection_name == 'full':
            return Config.TAXII_FULL
        if collection_name == 'ip':
            return Config.TAXII_IP
        if collection_name == 'domain':
            return Config.TAXII_DOMAIN
        if collection_name == 'url':
            return Config.TAXII_URL

        raise RunTimeException('Invalid TAXII collection name. Use: full, ip, domain, url')
