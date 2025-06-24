import os
import time
from datetime import timedelta

from anyrun.connectors import FeedsConnector


def load_indicators_to_siem(indicators: list[dict]) -> None:
    print(f'Received: {len(indicators)} indicator(s)')


def main():
    with FeedsConnector(api_key) as connector:
        # Load all actual feeds since the specified date
        response = connector.get_taxii_stix(collection='url', modified_after='2025-01-01', limit=10000)
        load_indicators_to_siem(response.get('objects'))

        while True:
            # Load only feeds modified since the last request
            # You can use the match_revoked option to retrieve FalsePositive indicators and remove them from the SIEM
            print(f'Next fetch from date: {connector.taxii_delta_timestamp}')
            response = connector.get_taxii_stix(collection='url', match_revoked=True, get_delta=True)
            load_indicators_to_siem(response.get('objects'))
            time.sleep(timedelta(hours=2).seconds)


if __name__ == '__main__':
    api_key = os.getenv('ANY_RUN_FEEDS_API_KEY')
    main()
