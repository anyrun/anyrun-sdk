from typing import Optional

from anyrun.iterators.threat_intelligence.feeds import StixFeedsIterator, MispFeedsIterator, NetworkIOCsFeedsIterator
from anyrun.connectors import FeedsConnector


class FeedsIterator:
    """ Iterator Factory. Creates a concrete iterator instance according to the method called """
    @staticmethod
    def stix(
            connector: FeedsConnector,
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
            limit: int = 100
    ) -> StixFeedsIterator:
        """
        Iterates through the stix feeds.

        :param connector: Connector instance
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
        :return: StixFeedsIterator instance
        """
        return StixFeedsIterator(
            connector=connector,
            chunk_size=chunk_size,
            ssl=ssl,
            ip=ip,
            url=url,
            domain=domain,
            file=file,
            port=port,
            show_revoked=show_revoked,
            get_new_ioc=get_new_ioc,
            period=period,
            date_from=date_from,
            date_to=date_to,
            limit=limit
        )

    @staticmethod
    def misp(
            connector: FeedsConnector,
            chunk_size: int = 1,
            ssl: bool = False,
            ip: bool = True,
            url: bool = True,
            domain: bool = True,
            show_revoked: bool = False,
            get_new_ioc: bool = False,
            period: Optional[str] = None,
            date_from: Optional[int] = None,
            date_to: Optional[int] = None,
            limit: int = 100
    ) -> MispFeedsIterator:
        """
        Iterates through the misp feeds.

        :param connector: Connector instance
        :param chunk_size: The number of feed objects to be retrieved each iteration.
            If greater than one, returns the list of objects
        :param ssl: Enable/disable ssl verification
        :param ip: Enable or disable the IP type from the feed
        :param url: Enable or disable the URL type from the feed
        :param domain: Enable or disable the Domain type from the feed
        :param show_revoked: Enable or disable receiving revoked feeds in report
        :param get_new_ioc: Receive only updated IOCs since the last request
        :param period: Time period to receive IOCs. Supports: day, week, month
        :param date_from: Beginning of the time period for receiving IOCs in timestamp format
        :param date_to: Ending of the time period for receiving IOCs in timestamp format
        :param limit: Number of tasks on a page. Default, all IOCs are included
        :return: MispFeedsIterator instance
        """
        return MispFeedsIterator(
            connector=connector,
            chunk_size=chunk_size,
            ssl=ssl,
            ip=ip,
            url=url,
            domain=domain,
            show_revoked=show_revoked,
            get_new_ioc=get_new_ioc,
            period=period,
            date_from=date_from,
            date_to=date_to,
            limit=limit
        )

    @staticmethod
    def network_iocs(
            connector: FeedsConnector,
            chunk_size: int = 1,
            ssl: bool = False,
            ip: bool = True,
            url: bool = True,
            domain: bool = True,
            show_revoked: bool = False,
            get_new_ioc: bool = False,
            period: Optional[str] = None,
            date_from: Optional[int] = None,
            date_to: Optional[int] = None,
            limit: int = 100
    ) -> NetworkIOCsFeedsIterator:
        """
        Iterates through the network_iocs feeds.

        :param connector: Connector instance
        :param chunk_size: The number of feed objects to be retrieved each iteration.
            If greater than one, returns the list of objects
        :param ssl: Enable/disable ssl verification
        :param ip: Enable or disable the IP type from the feed
        :param url: Enable or disable the URL type from the feed
        :param domain: Enable or disable the Domain type from the feed
        :param show_revoked: Enable or disable receiving revoked feeds in report
        :param get_new_ioc: Receive only updated IOCs since the last request
        :param period: Time period to receive IOCs. Supports: day, week, month
        :param date_from: Beginning of the time period for receiving IOCs in timestamp format
        :param date_to: Ending of the time period for receiving IOCs in timestamp format
        :param limit: Number of tasks on a page. Default, all IOCs are included
        :return: NetworkIOCsFeedsIterator instance
        """
        return NetworkIOCsFeedsIterator(
            connector=connector,
            chunk_size=chunk_size,
            ssl=ssl,
            ip=ip,
            url=url,
            domain=domain,
            show_revoked=show_revoked,
            get_new_ioc=get_new_ioc,
            period=period,
            date_from=date_from,
            date_to=date_to,
            limit=limit
        )
