from typing import Optional
from typing_extensions import override

from anyrun.iterators.base_iterator import BaseIterator
from anyrun.connectors.threat_intelligence.feeds_connector import FeedsConnector


class NetworkIOCsFeedsIterator(BaseIterator):
    def __init__(
            self,
            connector: FeedsConnector,
            chunk_size: int = 1,
            ip: bool = True,
            url: bool = True,
            domain: bool = True,
            show_revoked: bool = False,
            get_new_ioc: bool = False,
            period: Optional[str] = None,
            date_from: Optional[int] = None,
            date_to: Optional[int] = None,
            limit: int = 100
    ) -> None:
        """
        Iterates through the feeds objects.

        :param connector: Connector instance
        :param chunk_size: The number of feed objects to be retrieved each iteration.
            If greater than one, returns the list of objects
        :param ip: Enable or disable the IP type from the feed
        :param url: Enable or disable the URL type from the feed
        :param domain: Enable or disable the Domain type from the feed
        :param show_revoked: Enable or disable receiving revoked feeds in report
        :param get_new_ioc: Receive only updated IOCs since the last request
        :param period: Time period to receive IOCs. Supports: day, week, month
        :param date_from: Beginning of the time period for receiving IOCs in timestamp format
        :param date_to: Ending of the time period for receiving IOCs in timestamp format
        :param limit: Number of tasks on a page. Default, all IOCs are included
        """
        super().__init__(connector, chunk_size=chunk_size)

        self._query_params = {
            'ip': ip,
            'url': url,
            'domain': domain,
            'show_revoked': show_revoked,
            'get_new_ioc': get_new_ioc,
            'period': period,
            'date_from': date_from,
            'date_to': date_to,
            'limit': limit
        }

    @override
    async def _read_next_chunk(self) -> None:
        """ Overrides parent method using TI Feeds requests """
        self._buffer = await self._connector.get_network_iocs_async(
            **self._query_params,
            page=self._pages_counter
        )

        self._pages_counter += 1
