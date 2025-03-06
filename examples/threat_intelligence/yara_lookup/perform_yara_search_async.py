import os
import asyncio

import aiofiles

from anyrun.connectors import YaraLookupConnector


async def load_yara_rule() -> str:
    async with aiofiles.open('yara_lookup_rule_sample.txt', 'r') as file:
        return await file.read()


async def main():
    async with YaraLookupConnector(api_key) as connector:
        search_id = await connector.run_yara_search_async(await load_yara_rule())

        async for status in connector.get_search_status_async(search_id):
            print(status)

        report = await connector.get_stix_search_result_async(search_id, simplify=True)
        print(report if report else 'No threats were found during the analysis')


if __name__ == '__main__':
    api_key = os.getenv('ANY_RUN_Lookup_API_KEY')
    asyncio.run(main())
