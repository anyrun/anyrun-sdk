import os

from anyrun.connectors import FeedsConnector
from anyrun.iterators import FeedsIterator


def main():
    with FeedsConnector(api_key) as connector:
        for feed in FeedsIterator.taxii_stix(connector, chunk_size=5, collection='full', match_version='all'):
            print(feed)


if __name__ == '__main__':
    api_key = os.getenv('ANY_RUN_FEEDS_API_KEY')
    main()
