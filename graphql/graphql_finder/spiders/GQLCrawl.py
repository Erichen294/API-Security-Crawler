import json
from vuln_scan import *
from graphql_spider import *
from generate_schema_image import *

def print_banner():
    banner = r"""
    ========================================================================================================================================================================
    
     ██████  ██████   █████  ██████  ██   ██  ██████  ██          ███████  ██████  █████  ███    ██ ███    ██ ███████ ██████  
    ██       ██   ██ ██   ██ ██   ██ ██   ██ ██    ██ ██          ██      ██      ██   ██ ████   ██ ████   ██ ██      ██   ██ 
    ██   ███ ██████  ███████ ██████  ███████ ██    ██ ██          ███████ ██      ███████ ██ ██  ██ ██ ██  ██ █████   ██████  
    ██    ██ ██   ██ ██   ██ ██      ██   ██ ██ ▄▄ ██ ██               ██ ██      ██   ██ ██  ██ ██ ██  ██ ██ ██      ██   ██ 
     ██████  ██   ██ ██   ██ ██      ██   ██  ██████  ███████     ███████  ██████ ██   ██ ██   ████ ██   ████ ███████ ██   ██ 
                                                ▀▀                                                                           

    ========================================================================================================================================================================
                                                                                                                                                                      
    """
    print(banner)
    print("Welcome to the GRAPHQL Scanner")
    print("This tool tests various GraphQL security vulnerabilities on specified endpoints.\n")


def generate_report(url):
    results = {}

    # Run tests and collect results
    results['Introspection'] = test_introspection(url)
    results['Resource Request'] = check_resource_request(url)
    results['DoS Attack'] = test_dos_attack(url)
    results['Alias Attack'] = test_alias_attack(url)
    results['Sensitive Data'] = test_sensitive_data(url)
    results['Deep Recursion'] = test_deep_recursion_attack(url)
    results['SSRF Vulnerability'] = test_ssrf_vulnerability(url)
    results['SQL Injection'] = test_sql_injection(url)
    results['Path Traversal'] = test_path_traversal(url)
    results['Permissions'] = test_permissions(url)
    results['Get Users'] = test_getUsers(url)
    # results['Denial of Service'] = test_denialOfService(url)
    results['Unauthorized Comment'] = test_unauthorized_comment(url)
    results['Batching Attack'] = test_batching_attack(url)
    results['Field Limiting'] = test_field_limiting(url)
    results['Unauthorized Mutation'] = test_unauthorized_mutation(url)

    return results

def print_report(results):
    for test, result in results.items():
        print(f"Test: {test}")
        print(f"Result: {result}")
        print("-" * 40)


# Define the GraphQL endpoint URL
def load_endpoints(filename):
    with open(filename, "r") as file:
        for line in file:
            yield json.loads(line)['url']


if __name__ == "__main__":
    print_banner()
    choice = input("Do you want to enter an endpoint manually or crawl through the web application? Enter 'manual' or 'crawl': ").strip().lower()
    
    if choice == 'manual':
        url = input("Enter the GraphQL endpoint URL: ")
        GRAPHQL_URL = url 
        schema = input("Do you want to generate a schema visualization (if introspection is enabled)? Enter 'Y' or 'N': ")
        if schema.lower() == 'y':
            schema_table = fetch_graphql_schema(url)
            if schema_table:
                schema_filename = "schema.json"
                output_image_file = "schema.png"
                save_schema_to_file(schema_table, schema_filename)
                execute_graphqlviz(schema_filename, output_image_file)
        else:
            print("GraphQL schema not fetched or failed to fetch.")
        report_results = generate_report(GRAPHQL_URL)
        print_report(report_results)
    elif choice == 'crawl':
        starting_url = input("Enter the starting URL for the spider: ")
        authorization = input("Does your application need authorization? Enter 'Y' or 'N': ")
        schema = input("Do you want to generate a schema visualization (if introspection is enabled)? Enter 'Y' or 'N': ")
        authorization_key = None
        if authorization == 'Y':
            authorization_key = input("Enter the authorization key: ")
        process = CrawlerProcess({
            'USER_AGENT': 'GQLCrawl/1.0'
        })
        process.crawl(GraphQLSpider, start_urls=[starting_url], authorization=authorization, authorization_key=authorization_key )
        process.start()
        for url in load_endpoints("./valid_endpoints.json"):
            GRAPHQL_URL = url
            report_results = generate_report(GRAPHQL_URL)
            print_report(report_results)
            if schema.lower() == 'y':
                schema_table = fetch_graphql_schema(url)
                if schema_table:
                    schema_filename = "schema.json"
                    output_image_file = "schema.png"
                    save_schema_to_file(schema_table, schema_filename)
                    execute_graphqlviz(schema_filename, output_image_file)
            else:
                print("GraphQL schema not fetched or failed to fetch.")