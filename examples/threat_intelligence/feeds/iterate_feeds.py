import os

from anyrun.connectors import FeedsConnector
from anyrun.iterators import FeedsIterator


def main():

    with FeedsConnector(api_key) as connector:
        for feed in FeedsIterator.stix(connector, period='week', chunk_size=5):
            print(feed)


if __name__ == '__main__':
    api_key = os.getenv('ANY_RUN_FEEDS_API_KEY')
    main()
