import os

from anyrun.connectors.threat_intelligence import FeedsConnector, FeedsIterator


def main():

    with FeedsConnector(api_key) as connector:
        for feed in FeedsIterator(connector, feed_format='network_iocs', period='week', chunk_size=5):
            print(feed)


if __name__ == '__main__':
    api_key = os.getenv('ANY_RUN_FEEDS_API_KEY')
    main()
