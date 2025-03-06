import os

from anyrun.connectors import YaraLookupConnector


def load_yara_rule() -> str:
    with open('yara_lookup_rule_sample.txt', 'r') as file:
        return file.read()


def main():
    with YaraLookupConnector(api_key) as connector:
        search_id = connector.run_yara_search(load_yara_rule())

        for status in connector.get_search_status(search_id):
            print(status)

        report = connector.get_search_result(search_id, simplify=True)
        print(report if report else 'No threats were found during the analysis')

if __name__ == '__main__':
    api_key = os.getenv('ANY_RUN_Lookup_API_KEY')
    main()
