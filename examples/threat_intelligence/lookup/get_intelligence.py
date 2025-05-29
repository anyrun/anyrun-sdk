import os
from pprint import pprint

from anyrun.connectors import LookupConnector


def main():
    with LookupConnector(api_key) as connector:
        lookup_result = connector.get_intelligence(domain_name='1.1.1.1', lookup_depth=30)
        pprint(lookup_result)


if __name__ == '__main__':
    api_key = os.getenv('ANY_RUN_Lookup_API_KEY')
    main()
