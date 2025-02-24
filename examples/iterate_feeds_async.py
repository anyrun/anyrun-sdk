import os
import asyncio

from anyrun.connectors.threat_intelligence import FeedsConnector, FeedsIterator


async def main():

    async with FeedsConnector(api_key) as connector:
        async for feed in FeedsIterator(connector, url=False, domain=False, chunk_size=50):
            print(feed)


if __name__ == '__main__':
    api_key = os.getenv('ANY_RUN_FEEDS_API_KEY')
    asyncio.run(main())
