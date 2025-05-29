import os
from pprint import pprint

from anyrun.connectors import FeedsConnector


def main():
    with FeedsConnector(api_key) as connector:
        feeds = connector.get_taxii_stix(collection='url', added_after='2025-01-01')
        pprint(feeds)


if __name__ == '__main__':
    api_key = os.getenv('ANY_RUN_FEEDS_API_KEY')
    main()
