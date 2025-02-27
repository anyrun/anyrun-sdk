import os
import asyncio
from pprint import pprint

from anyrun.connectors import LookupConnector


async def main():
    async with LookupConnector(api_key) as connector:
        lookup_result = await connector.get_intelligence_async(start_date='2025-01-01', domain_name='1.1.1.1')
        pprint(lookup_result)


if __name__ == '__main__':
    api_key = os.getenv('ANY_RUN_Lookup_API_KEY')
    asyncio.run(main())
