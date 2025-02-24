import asyncio
from typing import Optional
from typing_extensions import Self

from anyrun.connectors.threat_intelligence.feeds_connector import FeedsConnector

from anyrun.utils.utility_functions import execute_synchronously
from anyrun.utils.exceptions import IteratorInitException


class FeedsIterator:

    def __init__(
            self,
            feeds_connector: FeedsConnector,
            feed_format: str = 'stix',
            chunk_size: int = 1,
            ssl: bool = False,
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
    ) -> None:
        """
        Iterates through the feeds objects.
        Attention! File and port filters are temporary unavailable for the **misp** and **network_iocs** formats

        :param feeds_connector: Connector instance
        :param feed_format: Supports: stix, misp, network_iocs
        :param chunk_size: The number of feed objects to be retrieved each iteration.
            If greater than one, returns the list of objects
        :param ssl: Enable/disable ssl verification
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
        """
        self._check_chunk_size(chunk_size, limit)
        self._check_feed_format(feed_format)

        self._connector = feeds_connector

        self._chunk_size = chunk_size
        self._feeds: list[Optional[dict]] = []
        self._pages_counter = 1
        self._feed_format = feed_format

        self._ssl = ssl

        self._query_params = {
                'ip': ip,
                'url': url,
                'domain': domain,
                'file': file,
                'port': port,
                'show_revoked': show_revoked,
                'get_new_ioc': get_new_ioc,
                'period': period,
                'date_from': date_from,
                'date_to': date_to,
                'limit': limit
             }

        self._clear_query_parameters()

    def __iter__(self) -> Self:
        return self

    def __next__(self) -> list[Optional[dict]]:
        try:
            return execute_synchronously(self.__anext__)
        except StopAsyncIteration as exception:
            raise StopIteration from exception

    def __aiter__(self) -> Self:
        return self

    async def __anext__(self) -> list[Optional[dict]]:
        await self._read_next_feeds_chunk()

        if not self._feeds:
            raise StopAsyncIteration

        return await self._receive_feeds_chunk()

    async def _read_next_feeds_chunk(self) -> None:
        """ Iterates through feed pages """
        if len(self._feeds) == 0:
            if self._feed_format == 'stix':
                self._feeds = await self._connector.get_stix_async(
                    **self._query_params,
                    page=self._pages_counter,
                    ssl=self._ssl
                )
            if self._feed_format == 'misp':
                self._feeds = await self._connector.get_misp_async(
                    **self._query_params,
                    page=self._pages_counter,
                    ssl=self._ssl
                )
            if self._feed_format == 'network_iocs':
                self._feeds = await self._connector.get_network_iocs_async(
                    **self._query_params,
                    page=self._pages_counter,
                    ssl=self._ssl
                )

            self._pages_counter += 1

    async def _receive_feeds_chunk(self) -> list[Optional[dict]]:
        """
        Returns the next feeds chunk. Returns a single feed if chunk size is equal one.
        Uses asyncio.Lock() to securely use the list

        :return: A single feed or list of feeds
        """
        async with asyncio.Lock():
            if self._chunk_size == 1:
                return self._feeds.pop(0)

            feeds_chunk = self._feeds[:self._chunk_size]
            del self._feeds[:self._chunk_size]

            return feeds_chunk

    @staticmethod
    def _check_chunk_size(chunk_size: int, allowed_chunk_size: int) -> None:
        """
        Checks if specified chunk size is not greater than request limit parameter value

        :param chunk_size:
        :param allowed_chunk_size:
        :raises IteratorInitException: If chunk size is greater than request limit parameter value
        """
        if chunk_size > allowed_chunk_size:
            raise IteratorInitException('The iterator chunk size can not be greater than config limit value')

    @staticmethod
    def _check_feed_format(feed_format: str) -> None:
        """
        Checks if specified feed_format is allowed

        :param feed_format: Specified feed format
        :raises IteratorInitException: If feed_format is invalid
        """
        if feed_format not in ('stix', 'misp', 'network_iocs'):
            raise IteratorInitException('The feed format is invalid. Expected: stix, misp, network_iocs')

    def _clear_query_parameters(self) -> None:
        """ Deletes some query filter fields according to feed type """
        if self._feed_format in ('misp', 'network_iocs'):
            self._query_params.pop('file')
            self._query_params.pop('port')
