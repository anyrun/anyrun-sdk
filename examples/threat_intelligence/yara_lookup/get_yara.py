import os
from pprint import pprint

from anyrun.connectors import YaraLookupConnector


def yara_rule() -> str:
    with open('yara_lookup_rule_sample.txt', 'r') as file:
        return file.read()


def main():
    with YaraLookupConnector(api_key) as connector:
        lookup_result = connector.get_yara(yara_rule())
        pprint(lookup_result)


if __name__ == '__main__':
    api_key = os.getenv('ANY_RUN_Lookup_API_KEY')
    main()
