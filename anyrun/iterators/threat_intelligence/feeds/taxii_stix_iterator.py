from typing import Optional
from typing_extensions import override

from anyrun.iterators.base_iterator import BaseIterator
from anyrun.connectors.threat_intelligence.feeds_connector import FeedsConnector


class TaxiiStixFeedsIterator(BaseIterator):
    def __init__(
            self,
            connector: FeedsConnector,
            chunk_size: int = 1,
            collection: str = 'full',
            match_type: Optional[str] = None,
            match_id: Optional[str] = None,
            match_version: str = 'last',
            match_revoked: bool = False,
            added_after: Optional[str] = None,
            modified_after: Optional[str] = None,
            limit: int = 100
    ) -> None:
        """
        Returns a list of ANY.RUN Feeds TAXII stix objects according to the specified query parameters

        :param collection: Collection type. Supports: full, ip, url, domain.
        :param match_type: Filter results based on the STIX object types. You can enter multiple values
            separated by commas
        :param match_id: IOC identifier.
        :param match_version: Filter STIX objects by their object version.
        :param match_revoked: Enable or disable receiving revoked feeds in report.
        :param added_after: Receive IOCs after specified date. Example: 2025-04-15.
        :param modified_after:
        :param limit: Number of tasks on a page. Default, all IOCs are included.
        :return: The list of feeds in **stix** format
        """
        super().__init__(connector, chunk_size=chunk_size)

        self._query_params = {
            'collection': collection,
            'match_type': match_type,
            'match_id': match_id,
            'match_revoked': match_revoked,
            'match_version': match_version,
            'modified_after': modified_after,
            'added_after': added_after,
            'limit': limit
        }

        self._taxii_page_id: Optional[str] = None
        self._stop_iteration: bool = False

    @override
    async def _read_next_chunk(self) -> None:
        """ Overrides parent method using TI Feeds requests """
        if self._stop_iteration:
            return

        response = await self._connector.get_taxii_stix_async(
            **self._query_params,
            next_page=self._taxii_page_id
        )

        next_page_id = response.get('next')

        if next_page_id:
            self._taxii_page_id = response.get('next')
        else:
            self._stop_iteration = True

        self._buffer = response.get('objects')
    