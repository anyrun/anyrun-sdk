import os

from anyrun.connectors import LookupConnector


def main():
    with LookupConnector(api_key) as connector:
        lookup_result = connector.get_intelligence(domain_name='1.1.1.1', lookup_depth=30, parse_response=True)

        if lookup_result.is_empty():
            print(f'The object is not found.')
            return

        print(lookup_result.verdict())
        print(lookup_result.intelligence_url('1.1.1.1'))
        print(lookup_result.file_meta())
        print(lookup_result.last_modified())
        print(lookup_result.tasks())
        print(lookup_result.tags())
        print(lookup_result.industries())
        print(lookup_result.country())
        print(lookup_result.asn())
        print(lookup_result.port())

        # You can also access lookup object fields directly
        print(lookup_result.related_urls)
        print(lookup_result.related_dns)
        print(lookup_result.related_ips)
        print(lookup_result.related_files)


if __name__ == '__main__':
    api_key = os.getenv('ANY_RUN_Lookup_API_KEY')
    main()
