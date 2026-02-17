import anyrun
from anyrun.connectors import FeedsConnector


def main():
    try:
        with FeedsConnector('super_secret_api_key') as connector:
            connector.get_taxii_stix()
    except anyrun.RunTimeException as exception:
        print(exception)
        print(f'Description: {exception.description}')
        print(f'Status code: {exception.status_code}')
        print(f'Summary: {exception.json}')


if __name__ == '__main__':
    main()
