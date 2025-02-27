import os

from anyrun.connectors import YaraLookupConnector
from anyrun.iterators import YaraIterator


def yara_rule() -> str:
    with open('yara_lookup_rule_sample.txt', 'r') as file:
        return file.read()


def main():
    with YaraLookupConnector(api_key) as connector:
        for match in YaraIterator.json(connector, yara_rule()):
            print(match)


if __name__ == '__main__':
    api_key = os.getenv('ANY_RUN_Lookup_API_KEY')
    main()
