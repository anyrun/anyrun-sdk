import os
import asyncio
from pprint import pprint

from anyrun.connectors import YaraLookupConnector

# You should use the aiofiles package instead
async def yara_rule() -> str:
    with open('yara_lookup_rule_sample.txt', 'r') as file:
        return file.read()


async def main():
    async with YaraLookupConnector(api_key) as connector:
        lookup_result = await connector.get_yara_async(await yara_rule())
        pprint(lookup_result)


if __name__ == '__main__':
    api_key = os.getenv('ANY_RUN_Lookup_API_KEY')
    asyncio.run(main())
