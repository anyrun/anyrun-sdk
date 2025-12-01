from typing import Optional, Union, Any
from datetime import datetime

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
        proxy_username: Optional[str] = None,
        proxy_password: Optional[str] = None,
        connector: Optional[aiohttp.BaseConnector] = None,
        timeout: int = Config.DEFAULT_REQUEST_TIMEOUT_IN_SECONDS,
        enable_requests: bool = False
    ) -> None:
        """
        :param api_key: ANY.RUN API-KEY in format: API-KEY <token> or Basic token in format: Basic <base64_auth>.
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
        super().__init__(
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
        )

        self._taxii_delta_timestamp: datetime = datetime(year=1970, month=1, day=1)

    @property
    def taxii_delta_timestamp(self) -> Optional[str]:
        if self._taxii_delta_timestamp:
            return self._taxii_delta_timestamp.strftime(Config.TAXII_DATE_FORMAT)

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
        match_type: str = 'indicator',
        match_id: Optional[str] = None,
        match_revoked: bool = False,
        match_version: str = 'all',
        added_after: Optional[str] = None,
        modified_after: Optional[str] = None,
        limit: int = 10000,
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
        match_type: str = 'indicator',
        match_id: Optional[str] = None,
        match_revoked: bool = False,
        match_version: str = 'all',
        added_after: Optional[str] = None,
        modified_after: Optional[str] = None,
        limit: int = 10000,
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

        if get_delta and self.taxii_delta_timestamp:
            modified_after = self.taxii_delta_timestamp

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
        await self._update_taxii_delta_timestamp()

        return response_data

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
                for param, value in params.items() if value is not None
            ]
        )
        return url + query_params

    async def _update_taxii_delta_timestamp(self) -> None:
        """ Updates taxii delta timestamp """
        delta_timestamp = self._response_headers.get('X-TAXII-Date-Modified-Last')

        if delta_timestamp:
            delta_timestamp = datetime.strptime(delta_timestamp, Config.TAXII_DATE_FORMAT)

            if (not self._taxii_delta_timestamp) or self._taxii_delta_timestamp < delta_timestamp:
                self._taxii_delta_timestamp = delta_timestamp

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
