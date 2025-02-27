from typing_extensions import override

from anyrun.iterators.base_iterator import BaseIterator
from anyrun.connectors.threat_intelligence.yara_lookup_connector import YaraLookupConnector


class JsonYaraIterator(BaseIterator):
    def __init__(
            self,
            connector: YaraLookupConnector,
            yara_rule: str,
            chunk_size: int = 1,
            ssl: bool = False,
    ) -> None:
        """
        Iterates through the yara search matches. Returns matches in **json** format

        :param connector: Connector instance
        :param yara_rule: Valid YARA rule
        :param chunk_size: The number of feed objects to be retrieved each iteration.
            If greater than one, returns the list of objects
        :param ssl: Enable/disable ssl verification
        """
        super().__init__(connector, chunk_size=chunk_size, ssl=ssl)

        self._yara_rule = yara_rule

    @override
    async def _read_next_chunk(self) -> None:
        """ Overrides parent method using Yara Lookup request """
        if self._pages_counter > 1:
            return

        self._buffer = await self._connector.get_yara_async(self._yara_rule, ssl=self._ssl)
        self._pages_counter += 1
