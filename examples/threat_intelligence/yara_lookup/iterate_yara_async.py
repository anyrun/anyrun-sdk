import os
import asyncio

from anyrun.connectors import YaraLookupConnector
from anyrun.iterators import YaraIterator

# You should use the aiofiles package instead
async def yara_rule() -> str:
    with open('yara_lookup_rule_sample.txt', 'r') as file:
        return file.read()


async def main():
    async with YaraLookupConnector(api_key) as connector:
        async for match in YaraIterator.stix(connector, await yara_rule()):
            print(match)


if __name__ == '__main__':
    api_key = os.getenv('ANY_RUN_Lookup_API_KEY')
    asyncio.run(main())
