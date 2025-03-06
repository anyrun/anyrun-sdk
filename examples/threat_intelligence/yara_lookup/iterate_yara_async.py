import os
import asyncio

import aiofiles

from anyrun.connectors import YaraLookupConnector
from anyrun.iterators import YaraIterator


async def load_yara_rule() -> str:
    async with aiofiles.open('yara_lookup_rule_sample.txt', 'r') as file:
        return await file.read()


async def main():
    async with YaraLookupConnector(api_key) as connector:
        async for match in YaraIterator.stix(connector, await load_yara_rule()):
            print(match)


if __name__ == '__main__':
    api_key = os.getenv('ANY_RUN_Lookup_API_KEY')
    asyncio.run(main())
