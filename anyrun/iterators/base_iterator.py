import asyncio
from typing import Optional
from typing_extensions import Self, Union
from abc import abstractmethod

from anyrun.connectors import FeedsConnector, YaraLookupConnector

from anyrun.utils.utility_functions import execute_synchronously


class BaseIterator:
    """ Implements custom iterator protocol """
    def __init__(
            self,
            connector: Union[FeedsConnector, YaraLookupConnector],
            chunk_size: int = 1
    ) -> None:
        """
        Iterates through the feeds objects.

        :param connector: Connector instance
        :param chunk_size: The number of feed objects to be retrieved each iteration.
            If greater than one, returns the list of objects
        """

        self._connector = connector
        self._chunk_size = chunk_size

        self._buffer: Union[list[Optional[dict]], dict] = []
        self._pages_counter = 1

    def __iter__(self) -> Self:
        return self

    def __next__(self) -> Union[list[Optional[dict]], dict]:
        try:
            return execute_synchronously(self.__anext__)
        except StopAsyncIteration as exception:
            raise StopIteration from exception

    def __aiter__(self) -> Self:
        return self

    async def __anext__(self) -> Union[list[Optional[dict]], dict]:
        if len(self._buffer) == 0:
            await self._read_next_chunk()

        if len(self._buffer) == 0:
            self._pages_counter = 1
            raise StopAsyncIteration

        return await self._read_buffer()

    @abstractmethod
    async def _read_next_chunk(self) -> None:
        """
        Executes the next request to the specified ANY.RUN endpoint and stores the result in a buffer.
        Method must be implemented in child iterators according to specific service requests
        """
        pass

    async def _read_buffer(self) -> Union[list[Optional[dict]], dict]:
        """
        Returns the next feeds chunk. Returns a single feed if chunk size is equal one.
        Uses asyncio.Lock() to securely use the list

        :return: A single feed or list of feeds
        """
        async with asyncio.Lock():
            if self._chunk_size == 1:
                return self._buffer.pop(0)

            next_chunk = self._buffer[:self._chunk_size]
            del self._buffer[:self._chunk_size]

            return next_chunk
