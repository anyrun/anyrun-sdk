import os
import asyncio
from datetime import datetime, timedelta

from anyrun.connectors.threat_intelligence import FeedsConnector


async def show_feeds(connector: FeedsConnector, page_number: int, timestamp: int) -> None:
    feeds = await connector.get_misp_async(date_from=timestamp, limit=150, page=page_number)
    print(feeds)


async def main():
    timestamp = int((datetime.now() - timedelta(days=150)).timestamp())

    async with FeedsConnector(api_key) as connector:
        tasks = [
            asyncio.create_task(show_feeds(connector, page_number, timestamp))
            for page_number in range(1, 5)
        ]

        await asyncio.gather(*tasks)


if __name__ == '__main__':
    api_key = os.getenv('ANY_RUN_FEEDS_API_KEY')
    asyncio.run(main())
