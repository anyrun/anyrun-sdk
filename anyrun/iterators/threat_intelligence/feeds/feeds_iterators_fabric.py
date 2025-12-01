from typing import Optional

from anyrun.connectors import FeedsConnector
from anyrun.iterators.threat_intelligence.feeds import TaxiiStixFeedsIterator


class FeedsIterator:
    """ Iterator Factory. Creates a concrete iterator instance according to the method called """
    @staticmethod
    def taxii_stix(
        connector: FeedsConnector,
        chunk_size: int = 1,
        collection: str = 'full',
        match_type: Optional[str] = 'indicator',
        match_id: Optional[str] = None,
        match_version: str = 'all',
        match_revoked: bool = False,
        added_after: Optional[str] = None,
        modified_after: Optional[str] = None,
        limit: int = 10000,
        get_delta: bool = False
    ) -> TaxiiStixFeedsIterator:
        """
        Iterates through the TAXII stix feeds.

        :param connector: Connector instance
        :param chunk_size: The number of feed objects to be retrieved each iteration.
        :param collection: Collection type. Supports: full, ip, url, domain.
        :param match_type: Filter results based on the STIX object types. You can enter multiple values
            separated by commas
        :param match_id: IOC identifier.
        :param match_version: Filter STIX objects by their object version.
        :param match_revoked: Enable or disable receiving revoked feeds in report.
        :param added_after: Receive IOCs after specified date. Example: 2025-04-15.
        :param modified_after: Receive IOCs after specified date. Example: 2025-04-15.
        :param limit: Number of tasks on a page. Default, all IOCs are included.
        :param get_delta: Get only indicators modified since the last request. Works starting from the second request
        :return: The list of feeds in **stix** format
        """
        return TaxiiStixFeedsIterator(
            connector=connector,
            chunk_size=chunk_size,
            collection=collection,
            match_type=match_type,
            match_id=match_id,
            match_revoked=match_revoked,
            match_version=match_version,
            modified_after=modified_after,
            added_after=added_after,
            limit=limit,
            get_delta=get_delta
        )
