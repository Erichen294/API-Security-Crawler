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


def generate_report(url, auth_token=None):
    results = {}

    # Run tests and collect results
    results['Introspection'] = test_introspection(url, auth_token)
    schema = fetch_schema(url, auth_token)  
    # Run dynamic tests if successful 
    if schema:
        results['Generate Schema'] = "Schema successfully fetched."
        results['Sensitive Data Dynamic Tests'] = test_sensitive_data_dynamically(url, schema, auth_token)
        results['Field Accessibility Tests'] = test_dynamic_field_accessibility(url, schema, auth_token)
        results['Mutation Tests'] = test_dynamic_mutation(url, schema, auth_token)
        results['Subscription Tests'] = test_dynamic_subscription(url, schema, auth_token)
    else:
        results['Generate Schema'] = "Failed to fetch schema."    
    # Static test cases 
    results['Resource Request'] = check_resource_request(url, auth_token)
    results['DoS Attack'] = test_dos_attack(url, auth_token)
    results['Alias Attack'] = test_alias_attack(url, auth_token)
    results['Deep Recursion'] = test_deep_recursion_attack(url, auth_token)
    results['SSRF Vulnerability'] = test_ssrf_vulnerability(url, auth_token)
    results['SQL Injection'] = test_sql_injection(url, auth_token)
    results['Path Traversal'] = test_path_traversal(url, auth_token)
    results['Permissions'] = test_permissions(url, auth_token)
    results['Get Users'] = test_getUsers(url, auth_token)
    results['Unauthorized Comment'] = test_unauthorized_comment(url, auth_token)
    results['Batching Attack'] = test_batching_attack(url, auth_token)
    results['Field Limiting'] = test_field_limiting(url, auth_token)
    results['Unauthorized Mutation'] = test_unauthorized_mutation(url, auth_token)
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
        authorization = input("Does your application need authorization? Enter 'Y' or 'N': ")
        authorization_key = None
        if authorization.lower() == 'y' :
            authorization_key = input("Enter the authorization key: ")
        schema = input("Do you want to generate a schema visualization (if introspection is enabled)? Enter 'Y' or 'N': ")
        if schema.lower() == 'y':
            schema_table = fetch_graphql_schema(url, authorization_key)
            if schema_table:
                schema_filename = "schema.json"
                output_image_file = "schema.png"
                save_schema_to_file(schema_table, schema_filename)
                execute_graphqlviz(schema_filename, output_image_file)
        else:
            print("GraphQL schema not fetched or failed to fetch.")
        report_results = generate_report(GRAPHQL_URL, authorization_key)
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
            report_results = generate_report(GRAPHQL_URL, authorization_key)
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