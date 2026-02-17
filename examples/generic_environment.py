import os
from pprint import pprint
from anyrun.connectors import LookupConnector
from anyrun.connectors.generic_environment import GenericEnvironment


def main():
    # Send a direct request using custom parameters
    generic_connector = GenericEnvironment("https://custom_endpoint_name")
    lookup_result = generic_connector.generic_request(api_key, "POST", json={"query": 'destinationIP:"1.1.1.1"'})
    pprint(lookup_result)

    # Set a custom request URL and use any default connector
    with GenericEnvironment("https://custom_endpoint_name"):
        with LookupConnector(api_key) as connector:
            lookup_result = connector.get_intelligence(destination_ip='1.1.1.1')
            pprint(lookup_result)


if __name__ == '__main__':
    api_key = os.getenv('ANY_RUN_Lookup_API_KEY')
    main()
