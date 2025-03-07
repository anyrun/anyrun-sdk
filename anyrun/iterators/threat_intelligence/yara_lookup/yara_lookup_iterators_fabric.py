from anyrun.iterators.threat_intelligence.yara_lookup import StixYaraIterator, JsonYaraIterator
from anyrun.connectors import YaraLookupConnector


class YaraIterator:
    """ Iterator Factory. Creates a concrete iterator instance according to the method called """
    @staticmethod
    def stix(
            connector: YaraLookupConnector,
            yara_rule: str,
            chunk_size: int = 1
    ) -> StixYaraIterator:
        """
        Iterates through the yara search matches. Returns matches in **json** format

        :param connector: Connector instance
        :param yara_rule: Valid YARA rule
        :param chunk_size: The number of feed objects to be retrieved each iteration.
            If greater than one, returns the list of objects
        :return: StixYaraIterator instance
        """
        return StixYaraIterator(
            connector=connector,
            chunk_size=chunk_size,
            yara_rule=yara_rule
        )

    @staticmethod
    def json(
            connector: YaraLookupConnector,
            yara_rule: str,
            chunk_size: int = 1
    ) -> JsonYaraIterator:
        """
        Iterates through the yara search matches. Returns matches in **json** format

        :param connector: Connector instance
        :param yara_rule: Valid YARA rule
        :param chunk_size: The number of feed objects to be retrieved each iteration.
            If greater than one, returns the list of objects
        """
        return JsonYaraIterator(
            connector=connector,
            chunk_size=chunk_size,
            yara_rule=yara_rule
        )
