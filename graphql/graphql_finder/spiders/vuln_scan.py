import requests
import json

# Define the GraphQL endpoint URL
def load_endpoints(filename):
    with open(filename, "r") as file:
        for line in file:
            yield json.loads(line)['url']

def save_results(details, test_name, status, response_data, query, filename="vulnerabilities.json"):
    """Appends detailed test results to a specified results file, including the query used."""
    with open(filename, 'a') as file:
        entry = {
            test_name: {
                "status": status,
                "details": details,
                "query": query,
                "response": response_data
            }
        }
        file.write(json.dumps(entry, indent=4) + "\n")

def get_headers(auth_token=None):
    """ Returns HTTP headers suitable for making requests. """
    headers = {'Content-Type': 'application/json'}
    if auth_token:
        headers['Authorization'] = f'Bearer {auth_token}'
    return headers

def test_dos_attack(url, schema=None, auth_token=None, results_filename="vulnerabilities.json"):
    """Tests for Denial of Service vulnerability using repeated query submission."""
    query = "query { systemUpdate }" * 100
    details = {
        "vulnerability": "Denial of Service (DoS)",
        "severity": "High",
        "description": "This test floods the server with repeated requests to check if the server can handle high load without service degradation or crash.",
        "remediation": "Implement rate limiting, use a robust load balancer, and consider auto-scaling."
    }
    try:
        status_codes = []
        for i in range(100):
            response = requests.post(url, json={"query": query}, headers=get_headers(auth_token))
            status_codes.append(response.status_code)
        # Summarizing response status codes
        status_summary = {status: status_codes.count(status) for status in set(status_codes)}
        if 200 not in status_codes:
            save_results(details, "DoS Attack", "Vulnerability Found", status_summary, query, results_filename)
            return "DoS attack vulnerability found."
        else:
            save_results(details, "DoS Attack", "No Vulnerability Found", status_summary, query, results_filename)
            return "DoS attack vulnerability not found."
    except Exception as e:
        save_results(details, "DoS Attack", "Test Failed", str(e), query, results_filename)
        return "DoS attack test failed."

def test_alias_attack(url, auth_token=None, results_filename="vulnerabilities.json"):
    """Tests for vulnerability to alias-based attacks."""
    query_list = [f"q{i}: systemUpdate" for i in range(1)]
    query = "{" + " ".join(query_list) + "}"
    details = {
        "vulnerability": "Alias-Based Attack",
        "severity": "Medium",
        "description": "Tests if the server handles numerous query aliases without significant performance drop or errors.",
        "remediation": "Limit the number of allowed aliases in queries to prevent abuse."
    }
    try:
        status_codes = []
        responses = []
        for i in range(1):
            response = requests.post(url, json={"query": query}, headers=get_headers(auth_token))
            status_codes.append(response.status_code)
            responses.append(response.json())
        response_summary = {
            "status_codes": status_codes[:10],  
            "sample_responses": responses[:3]  
        }
        if 200 not in status_codes:
            save_results(details, "Alias-Based Attack", "Vulnerability Found", response_summary, query, results_filename)
            return "Alias-based attack vulnerability found."
        else:
            save_results(details, "Alias-Based Attack", "No Vulnerability Found", response_summary, query, results_filename)
            return "Alias-based attack vulnerability not found."
    except Exception as e:
        save_results(details, "Alias-Based Attack", "Test Failed", str(e), query, results_filename)
        return "Alias-based attack test failed."

def construct_nested_query(field, schema, depth=100, used_types=None):
    if used_types is None:
        used_types = set()

    if depth <= 0 or field['name'] in used_types:
        return field['name']

    used_types.add(field['name']) 

    nested_query = f"{field['name']} "

    # Safely access nested properties
    field_type = field.get('type', {})
    of_type = field_type.get('ofType', {})

    # Check if ofType has fields and they are not None
    if of_type and 'fields' in of_type and of_type['fields'] is not None:
        for subfield in of_type['fields']:
            if subfield.get('type', {}).get('kind') == 'OBJECT' and subfield['name'] not in used_types:
                # Recursively call to construct deeper query parts
                nested_query += construct_nested_query(subfield, schema, depth - 1, used_types)
    return nested_query

def construct_deeply_nested_pair_query(field1, field2, depth):
    """Constructs a deeply nested query by alternating between two fields."""
    query = ""
    current_field = field1

    for _ in range(depth):
        if current_field == field1:
            query = f"{field1} {{ {query} {field2} {{"
            current_field = field2
        else:
            query = f"{field2} {{ {query} {field1} {{"
            current_field = field1

    # Close all opened braces
    query += " }" * (depth * 2)  # Each iteration opens two braces
    return f"query {{ {query} }}"

def test_deep_recursion_attack(url,schema=None, auth_token=None, results_filename="vulnerabilities.json"):
    schema = fetch_schema(url, auth_token)
    if not schema:
        print("Failed to fetch schema or schema is empty.")
        return "Failed to fetch schema or schema is empty."

    details = {
        "vulnerability": "Deep Recursion Query",
        "severity": "Medium",
        "description": "Tests server's ability to handle deeply nested and interconnected queries.",
        "remediation": "Implement depth limiting on GraphQL queries."
    }
    test_results = []
    test_list = []
    for type_info in schema:
        if 'fields' in type_info and type_info['fields']:
            for field in type_info['fields']:
                if field.get('type', {}).get('kind') == 'OBJECT':
                    test_list.append(construct_nested_query(field, schema, 10))
                    if (len(test_list) > 1):
                        query = construct_deeply_nested_pair_query(test_list[0],test_list[1], 10)
                        response = requests.post(url, json={"query": query}, headers=get_headers(auth_token))
                        if response.status_code != 200 or 'errors' in response.json():
                            test_results.append("Vulnerability Found")
                            save_results(details, f"Deep Recursion Test on {type_info['name']}", "Vulnerability Found", response.json(), query, results_filename)
                        test_list = []
    return "Vulnerability Found" if "Vulnerability Found" in test_results else "No vulnerabilities found"



def test_ssrf_vulnerability(url, schema=None,auth_token=None, results_filename="vulnerabilities.json"):
    schema = fetch_schema_deeper(url, auth_token)
    details = {
        "vulnerability": "Server-Side Request Forgery (SSRF)",
        "severity": "High",
        "description": "Occurs when an attacker can make the server perform malicious requests on their behalf, potentially accessing internal resources or performing actions on other systems.",
        "remediation": "Ensure that server-side code properly validates and sanitizes all user-supplied inputs, and restricts access to sensitive resources."
    }
    test_results = []

    for type_info in schema:
        if 'fields' in type_info:
            for field in type_info['fields']:
                if 'url' in field['name'].lower():  # Improved check for field names containing 'url'
                    query = f"{{ {type_info['name']} {{ {field['name']} }} }}"
                    try:
                        response = requests.post(url, json={"query": query}, headers=get_headers(auth_token))
                        if response.status_code == 200:
                            test_results.append(f"Potential SSRF vulnerability found in {type_info['name']}.")
                            save_results(details, f"SSRF Vulnerability Test on {type_info['name']}", "Vulnerability Found", response.json(), query, results_filename)
                        else:
                            save_results(details, f"SSRF Vulnerability Test on {type_info['name']}", "No Vulnerability Found", response.json(), query, results_filename)
                    except Exception as e:
                        save_results(details, f"SSRF Vulnerability Test on {type_info['name']}", "Error During Test", str(e), query, results_filename)

    return "Potential vulnerability found" if any("Vulnerability Found" in result for result in test_results) else "No vulnerabilities found"

def test_sql_injection(url, auth_token=None, schema=None, results_filename="vulnerabilities.json"):
    if not schema:
        schema = fetch_schema_deeper(url, auth_token)
    if not schema:
        return "Failed to fetch schema or no schema available."

    details = {
        "vulnerability": "SQL Injection",
        "severity": "High",
        "description": "Allows attackers to execute arbitrary SQL queries on the server's database.",
        "remediation": "Use parameterized queries or prepared statements."
    }

    vulnerabilities_found = False

    for type_info in schema:
        if 'fields' in type_info:
            for field in type_info['fields']:
                if any(arg['type']['name'] == 'String' for arg in field.get('args', [])):
                    for arg in field['args']:
                        if arg['type']['name'] == 'String':  # Ensuring the argument is of type String
                            injection_query = {
                                "query": f"""
                                query {{
                                    {field['name']}({arg['name']}:"' OR ''='") {{
                                        {arg['name']}
                                    }}
                                }}
                                """
                            }
                            try:
                                response = requests.post(url, json=injection_query, headers=get_headers(auth_token))
                                response_json = response.json()
                                if response.status_code == 200 and 'errors' not in response_json:
                                    save_results(details, f"SQL Injection Test on {field['name']} using {arg['name']}", "Vulnerability Found", response.status_code, injection_query["query"], results_filename)
                                    vulnerabilities_found = True
                                else:
                                    save_results(details, f"SQL Injection Test on {field['name']} using {arg['name']}", "No Vulnerability Found", response.status_code, injection_query["query"], results_filename)
                            except Exception as e:
                                save_results(details, f"SQL Injection Test on {field['name']} using {arg['name']}", "Error During Test", str(e), injection_query["query"], results_filename)

    return "SQL injection vulnerabilities found." if vulnerabilities_found else "No SQL injection vulnerabilities found."


def test_sql_injections(url, auth_token, schema, results_filename='vulnerabilities.json'):
    """Tests for SQL Injection vulnerabilities specifically targeting the 'pasts' field with a 'filter' argument."""
    injection_query=schema
    
    headers = get_headers(auth_token)
    response = requests.post(url, json=injection_query, headers=headers)
    response_json = response.json()

    details = {
        "vulnerability": "SQL Injection",
        "severity": "High",
        "description": "Attempts to exploit SQL injection vulnerabilities by injecting malicious SQL code through GraphQL queries.",
        "remediation": "Use parameterized queries or prepared statements to handle user input."
    }

    if response.status_code == 200 and 'errors' in response_json:
        # If errors are present in the response, it might indicate an SQL injection vulnerability
        save_results(details, "SQL Injection Test on 'pastes' field", "Vulnerability Found", response_json, injection_query['query'], results_filename)
        return "SQL injection vulnerability found."
    elif response.status_code != 200:
        save_results(details, "SQL Injection Test on 'pastes' field", "No Vulnerability Found (HTTP Error)", response_json, injection_query['query'], results_filename)
        return "Potential vulnerability, HTTP error occurred."
    else:
        save_results(details, "SQL Injection Test on 'pastes' field", "No Vulnerability Found", response_json, injection_query['query'], results_filename)
        return "No SQL injection vulnerabilities found."
    
def test_path_traversal(url,schema=None, auth_token=None, results_filename="vulnerabilities.json"):
    schema = fetch_schema_deeper(url, auth_token)
    if not schema:
        return "Failed to fetch schema or no schema available."

    details = {
        "vulnerability": "Path Traversal",
        "severity": "High",
        "description": "Test to identify if file operations allow navigation to parent directories, potentially accessing unauthorized files."
    }

    vulnerable = []
    headers = get_headers(auth_token)
    # Iterate over mutation fields in the schema
    for field in schema:
        if any(arg['name'] == 'filename' for arg in field.get('args', [])):  # Check if filename argument exists
            path_traversal_query = {
                "query": f"""
                mutation {{
                    {field['name']}(filename:"../../../../../tmp/file.txt", content:"test") {{
                        result
                    }}
                }}
                """
            }
            try:
                response = requests.post(url, json=path_traversal_query, headers=headers)
                if response.status_code == 200 and 'data' in response.json() and response.json()['data'].get(field['name'], {}).get('result'):
                    vulnerable.append(f"{field['name']} is vulnerable to path traversal.")
                    save_results(details, f"Path Traversal Test on {field['name']}", "Vulnerability Found", response.json(), path_traversal_query['query'], results_filename)
            except Exception as e:
                save_results(details, f"Path Traversal Test on {field['name']}", "Error During Test", str(e), path_traversal_query['query'], results_filename)

    if vulnerable:
        return "Vulnerabilities detected: " + ", ".join(vulnerable)
    else:
        return "No path traversal vulnerabilities found."

def test_permissions(url,schema=None, auth_token=None, results_filename="vulnerabilities.json"):
    """Tests for authorization vulnerabilities by dynamically testing mutations based on schema introspection."""
    if not schema:
        schema = fetch_schema(url, auth_token)

    details = {
        "vulnerability": "Improper Authorization",
        "severity": "High",
        "description": "Occurs when mutations do not enforce proper authorization, allowing unauthorized modifications.",
        "remediation": "Implement and enforce strict authorization checks on all sensitive mutations."
    }

    test_results = []

    for mutation in schema:
        # Ensure mutation has 'args' and then check for 'userId' in args
        if 'args' in mutation and any(arg['name'] == 'userId' for arg in mutation['args']):
            mutation_query = f'''
            mutation {{
                {mutation['name']}(userId: "12345") {{
                    __typename
                }}
            }}
            '''
            try:
                response = requests.post(url, json={'query': mutation_query}, headers=get_headers(auth_token))
                if response.status_code in [403, 401]:
                    test_results.append(f"Proper authorization in place for '{mutation['name']}'.")
                    save_results(details, f"Authorization Test on {mutation['name']}", "No Vulnerability Found", response.json(), mutation_query, results_filename)
                else:
                    test_results.append(f"Authorization vulnerability detected in '{mutation['name']}'.")
                    save_results(details, f"Authorization Test on {mutation['name']}", "Vulnerability Found", response.json(), mutation_query, results_filename)
            except Exception as e:
                test_results.append(f"Error testing '{mutation['name']}': {str(e)}")
                save_results(details, f"Authorization Test on {mutation['name']}", "Error During Test", str(e), mutation_query, results_filename)

    return "Vulnerabilities detected." if any("Vulnerability Found" in result for result in test_results) else "No authorization vulnerabilities found."
    
def test_getUsers(url, auth_token=None, filename="vulnerabilities.json"):
    getUsers_query = {
        'query': '''
        query getUsers {
          users(where: {role: ADMINISTRATOR}) {
            edges {
              node {
                userId
                name
              }
            }
          }
        }
        '''
    }
    details = {
        "description": "Tests if user data for administrators can be fetched without proper authorization.",
        "severity": "High"
    }
    try:
        response = requests.post(url, json=getUsers_query, headers=get_headers(auth_token))
        response.raise_for_status()
        response_json = response.json()
        if 'data' in response_json and 'users' in response_json['data']:
            save_results(details, "Get Users Test", "Vulnerability Found", response_json, getUsers_query['query'], filename)
            return "Get users vulnerability found."
        else:
            save_results(details, "Get Users Test", "No Vulnerability Found", response_json, getUsers_query['query'], filename)
            return "Get users vulnerability not found."
    except Exception as e:
        save_results(details, "Get Users Test", "Test Not Applicable", str(e), getUsers_query['query'], filename)
        return f"Get users test not applicable."
    
def test_unauthorized_comment(url, schema=None, auth_token=None):
    comment_query = {
        "query": """
            mutation {
                createComment(input: {
                    postId: 1,
                    userId: 1,
                    content: "This is a test comment.",
                    clientMutationId: "UWHATM8",
                }) {
                    clientMutationId
                }
            }
        """
    }
    try:
        response = requests.post(url, json=comment_query, headers=get_headers(auth_token))
        if response.status_code == 200 and 'UWHATM8' in response.text:
            return "Unauthorized comment vulnerability found."
        else:
            return "Unauthorized comment vulnerability not found."
    except Exception as e:
        return f"An error occurred while testing unauthorized comment: {str(e)}"
    

def test_batching_attack(url, schema=None,auth_token=None, results_filename="vulnerabilities.json"):
    system_update_query = "query { systemUpdate }"
    queries = [system_update_query] * 1
    payload = json.dumps(queries)
    headers = get_headers(auth_token)
    
    try:
        response = requests.post(url, data=payload, headers=headers)
        if response.status_code != 200:
            # Log unexpected status codes
            error_details = {
                "status": response.status_code,
                "response": response.text
            }
            save_results("Error response from server", "Batching Attack Test", "HTTP Error", error_details, payload, results_filename)
            return f"HTTP error occurred: {response.status_code}"
        
        # Try to decode JSON only if response is 200
        response_json = response.json()
        if all('errors' not in resp for resp in response_json):
            save_results("Server handled batching well", "Batching Attack Test", "No Vulnerability Found", response_json, payload, results_filename)
            return "No vulnerabilities found, server handled batching well."
        else:
            save_results("Batching attack vulnerability found", "Batching Attack Test", "Vulnerability Found", response_json, payload, results_filename)
            return "Batching attack vulnerability found."
    except json.JSONDecodeError:
        save_results("Failed to decode JSON response", "Batching Attack Test", "JSON Decode Error", {"raw_response": response.text}, payload, results_filename)
        return "Failed to decode JSON from response."
    except Exception as e:
        save_results(str(e), "Batching Attack Test", "Error During Test", {"exception": str(e)}, payload, results_filename)
        return f"An error occurred: {str(e)}"


def test_unauthorized_mutation(url, schema=None,auth_token=None):
    mutation_query = 'mutation { updatePost(id: "1", data: { title: "New Title" }) { title } }'
    try:
        response = requests.post(url, json={"query": mutation_query}, headers=get_headers(auth_token))
        if response.status_code in [200, 201] and 'title' in response.json().get('data', {}):
            return "Unauthorized mutation vulnerability found."
        else:
            return "Unauthorized mutation vulnerability not found."
    except Exception as e:
        return f"Mutation test failed: {str(e)}"


def test_sensitive_data_dynamically(url, schema, auth_token=None, results_filename="vulnerabilities.json"):
    """ Dynamically test for sensitive data based on schema introspection. """
    sensitive_keywords = [
        'password', 'passcode', 'passwd', 'pin', 'creditcard', 'ccnumber', 'cardnum', 'ssn', 'socialsecuritynumber',
        'secret', 'token', 'apikey', 'api_key', 'accesstoken', 'access_token', 'auth', 'authentication', 'credentials',
        'privatekey', 'private_key', 'secretkey', 'secret_key', 'encryptionkey', 'encryption_key',
        'bank', 'accountnumber', 'account_num', 'routingnumber', 'routing_num', 'financial',
        'salary', 'birthdate', 'birthplace', 'passportnumber', 'passport_num', 'driverlicense', 'driver_license_num',
        'address', 'email', 'phone', 'phonenumber', 'mobile', 'cell', 'contact', 'zip', 'postal', 'postcode',
        'signature', 'profile', 'ssn', 'dni', 'nationalid', 'national_id', 'taxid', 'tax_id', 'health', 'insurance',
        'beneficiary', 'beneficiary_id', 'custodian', 'guardian', 'sessionid', 'session_id', 'cookie', 'authentication_token'
    ]
    sensitive_fields = []
    findings = []

    for type_info in schema:
        if type_info.get('fields'):
            for field in type_info['fields']:
                if any(keyword in field['name'].lower() for keyword in sensitive_keywords):
                    sensitive_fields.append((type_info['name'], field['name']))

    for type_name, field_name in sensitive_fields:
        query = f'{{ {type_name} {{ {field_name} }} }}'
        response = requests.post(url, json={'query': query}, headers=get_headers(auth_token))
        result_detail = {
            "type": type_name,
            "field": field_name,
            "query": query,
            "status_code": response.status_code
        }
        if response.status_code == 200 and response.json().get('data', {}).get(type_name):
            findings.append("Vulnerability Found")
            save_results(result_detail, "Sensitive Data Test", "Data Leak Detected", response.json(), query, results_filename)
        else:
            findings.append("No Vulnerability Found")

    return "Vulnerability Found" if "Vulnerability Found" in findings else "No vulnerabilities found"


def test_dynamic_nested_query(url, schema, auth_token=None, results_filename="vulnerabilities.json"):
    findings = []
    for type_info in schema:
        if type_info.get('fields'):
            query_fields = []
            for field in type_info['fields']:
                if field['type']['kind'] == 'OBJECT':
                    nested_fields = ' '.join([nested_field['name'] for nested_field in field['type'].get('fields', []) if nested_field['type']['kind'] != 'OBJECT'])
                    if nested_fields:
                        query_fields.append(f"{field['name']} {{ {nested_fields} }}")
            if query_fields:
                full_query = f'{{ {type_info["name"]} {{ ' + ' '.join(query_fields) + ' }} }}'
                response = requests.post(url, json={'query': full_query}, headers=get_headers(auth_token))
                result_detail = {
                    "type_info": type_info["name"],
                    "query": full_query,
                    "status_code": response.status_code
                }
                if response.status_code != 200:
                    findings.append("Vulnerability Found")
                    save_results(result_detail, "Dynamic Nested Query Test", "Vulnerability Found", response.json(), full_query, results_filename)
                else:
                    findings.append("No Vulnerability Found")

    return "Vulnerability Found" if "Vulnerability Found" in findings else "No vulnerabilities found"


def test_dynamic_field_accessibility(url, schema, auth_token=None, results_filename="vulnerabilities.json"):
    restricted_keywords = ['admin', 'restricted', 'private', 'confidential']
    findings = []

    for type_info in schema:
        if type_info.get('fields'):
            for field in type_info['fields']:
                if any(keyword in field['name'].lower() for keyword in restricted_keywords):
                    query = f'{{ {type_info["name"]} {{ {field["name"]} }} }}'
                    response = requests.post(url, json={'query': query}, headers=get_headers(auth_token))
                    result_detail = {
                        "field": field['name'],
                        "type": type_info['name'],
                        "query": query,
                        "status_code": response.status_code
                    }
                    if response.status_code == 200 and response.json().get('data', {}).get(type_info['name']):
                        findings.append("Vulnerability Found")
                        save_results(result_detail, "Dynamic Field Accessibility Test", "Unauthorized Access Detected", response.json(), query, results_filename)
                    else:
                        findings.append("No Vulnerability Found")

    return "Vulnerability Found" if "Vulnerability Found" in findings else "No vulnerabilities found"


def test_dynamic_mutation(url, schema, auth_token=None, results_filename="vulnerabilities.json"):
    mutation_keywords = ['update', 'create', 'delete', 'add', 'remove', 'set']
    findings = []

    for type_info in schema:
        if type_info.get('fields'):
            for field in type_info['fields']:
                if 'mutation' in type_info['name'].lower() or any(keyword in field['name'].lower() for keyword in mutation_keywords):
                    mutation_query = f'mutation {{ {field["name"]}(input: {{}}) {{ id }} }}'
                    response = requests.post(url, json={'query': mutation_query}, headers=get_headers(auth_token))
                    result_detail = {
                        "field": field['name'],
                        "type": type_info['name'],
                        "query": mutation_query,
                        "status_code": response.status_code
                    }
                    if response.status_code == 200:
                        findings.append("Vulnerability Found")
                        save_results(result_detail, "Dynamic Mutation Test", "Mutation Possible", response.json(), mutation_query, results_filename)
                    else:
                        findings.append("No Vulnerability Found")

    return "Vulnerability Found" if "Vulnerability Found" in findings else "No vulnerabilities found"


def test_dynamic_subscription(url, schema, auth_token=None, results_filename="vulnerabilities.json"):
    """Tests GraphQL subscriptions for unauthorized access or data leakage issues."""
    findings = []
    for type_info in schema:
        if 'subscription' in type_info['name'].lower():
            for field in type_info['fields']:
                subscription_query = f'subscription {{ {field["name"]} {{ id }} }}'
                response = requests.post(url, json={'query': subscription_query}, headers=get_headers(auth_token))
                result_detail = {
                    "type": type_info['name'],
                    "field": field['name'],
                    "query": subscription_query,
                    "status_code": response.status_code
                }
                if response.status_code == 200:
                    findings.append("Vulnerability Found")
                    save_results(result_detail, "Subscription Test", "Potential Data Leakage", response.json(), subscription_query, results_filename)
                else:
                    findings.append("No Vulnerability Found")

    return "Vulnerability Found" if "Vulnerability Found" in findings else "No vulnerabilities found"


def test_denialOfService(url, schema=None, auth_token=None):
    # 100 for both correctly tests DVGA without completely crashing
    # 10000 and 1000 correctly tests WP
    # 10000 and 1000 correctly tests Saleor
    FORCE_MULTIPLIER = 100
    CHAINED_REQUESTS = 100
    queries = []
    
    payload = 'content \n comments { \n nodes { \n content } }' * FORCE_MULTIPLIER
    query = {'query':'query { \n posts { \n nodes { \n ' + payload + '} } }'}
    
    for _ in range(0, CHAINED_REQUESTS):
        queries.append(query)

    r = requests.post(url, json=queries)
    if (r.status_code == 200):
        return "Denial of Service vulnerability not found. The server is still responsive."
    else:
        return "Denial of Service vulnerability found. The server may have crashed or become unresponsive."
    
def fetch_schema(url, auth_token=None):
    introspection_query = {
        "query": """
        query IntrospectionQuery {
            __schema {
                types {
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
            }
        }
        """
    }
    headers = get_headers(auth_token)
    response = requests.post(url, json=introspection_query, headers=headers)
    if response.status_code == 200:
        schema_data = response.json()['data']['__schema']['types']
        return schema_data
    else:
        print(f"Failed to fetch schema: {response.status_code}")
        return None
    
def fetch_schema_deeper(url, auth_token=None):
    """ Fetch the GraphQL schema via introspection. """
    introspection_query = {
        "query": """
        query IntrospectionQuery {
            __schema {
                queryType {
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
                        args {
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
                }
                mutationType {
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
                        args {
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
                }
            }
        }
        """
    }
    headers = get_headers(auth_token)
    response = requests.post(url, json=introspection_query, headers=headers)
    if response.status_code == 200:
        schema_data = response.json()['data']['__schema']
        # Combine both query and mutation types into a single list
        schema = []
        if 'queryType' in schema_data:
            schema.extend(schema_data['queryType']['fields'])
        if 'mutationType' in schema_data and schema_data['mutationType']:
            schema.extend(schema_data['mutationType']['fields'])
        return schema
    else:
        print(f"Failed to fetch schema: {response.status_code}")
        return None

