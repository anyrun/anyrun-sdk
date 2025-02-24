import os
from pprint import pprint

from anyrun.connectors.threat_intelligence import FeedsConnector


def main():
    with FeedsConnector(api_key) as connector:
        feeds = connector.get_stix(file=False, port=False, period='month')
        pprint(feeds)


if __name__ == '__main__':
    api_key = os.getenv('ANY_RUN_FEEDS_API_KEY')
    main()
