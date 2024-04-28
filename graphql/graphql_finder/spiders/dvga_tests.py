import requests

import uuid

from os import environ
import os.path

IP =  environ.get('WEB_HOST', '127.0.0.1')
PORT = environ.get('WEB_PORT', 5013)

URL = 'http://{}:{}'.format(IP, PORT)
GRAPHQL_URL = URL + '/graphql'
GRAPHIQL_URL = URL + '/graphiql'

def generate_id():
    return str(uuid.uuid4())[4]

def graph_query(url, query=None, operation="query", headers={}):
    return requests.post(url,
                            verify=False,
                            allow_redirects=True,
                            timeout=30,
                            headers=headers,
                            json={operation:query})

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


def test_batching():
    queries = [
        {"query":"query BATCH_ABC { pastes { title } }"},
        {"query":"query BATCH_DEF { pastes { content } }"}
    ]

    r = requests.post(GRAPHQL_URL, json=queries)
    assert r.status_code == 200
    assert isinstance(r.json(), list)
    assert len(r.json()) == 2
    for i in r.json():
        for paste in i['data']['pastes']:
            for field in paste.keys():
                assert field in ('title', 'content')

def test_batched_operation_names():
    r = requests.get(URL + '/audit')
    assert r.status_code == 200
    assert 'BATCH_ABC' in r.text
    assert 'BATCH_DEF' in r.text

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


"""
    DVGA Sanity Check
"""
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


def test_query_pastes():
    query = '''
    query {
      pastes {
        id
        ipAddr
        ownerId
        burn
        owner {
            id
            name
        }
        title
        content
        userAgent
      }
    }
    '''
    r = graph_query(GRAPHQL_URL, query)

    assert r.json()['data']['pastes'][0]['id']
    assert r.json()['data']['pastes'][0]['ipAddr']
    assert r.json()['data']['pastes'][0]['ownerId'] == 1
    assert r.json()['data']['pastes'][0]['burn'] == False
    assert r.json()['data']['pastes'][0]['owner']['id'] == '1'
    assert r.json()['data']['pastes'][0]['owner']['name'] == 'DVGAUser'
    assert r.json()['data']['pastes'][0]['title']
    assert r.json()['data']['pastes'][0]['userAgent']
    assert r.json()['data']['pastes'][0]['content']

def test_query_paste_by_id():
    query = '''
    query {
      paste (id: 1) {
        id
        ipAddr
        ownerId
        burn
        owner {
            id
            name
        }
        title
        content
        userAgent
      }
    }
    '''
    r = graph_query(GRAPHQL_URL, query)

    assert r.json()['data']['paste']['id'] == '1'
    assert r.json()['data']['paste']['ipAddr'] == '127.0.0.1'
    assert r.json()['data']['paste']['ownerId'] == 1
    assert r.json()['data']['paste']['burn'] == False
    assert r.json()['data']['paste']['owner']['id'] == '1'
    assert r.json()['data']['paste']['owner']['name'] == 'DVGAUser'
    assert r.json()['data']['paste']['title']
    assert r.json()['data']['paste']['userAgent'] == 'User-Agent not set'
    assert r.json()['data']['paste']['content']

def test_query_systemHealth():
    query = '''
        query {
           systemHealth
        }
    '''
    r = graph_query(GRAPHQL_URL, query)
    assert 'System Load' in r.json()['data']['systemHealth']
    assert '.' in r.json()['data']['systemHealth'].split('System Load: ')[1]

def test_query_systemUpdate():
    pass

def test_query_systemDebug():
    query = '''
        query {
           systemDebug
        }
    '''
    r = graph_query(GRAPHQL_URL, query)
    assert r.status_code == 200

    systemdebug_indicators = ['TTY', 'COMMAND']
    assert any(substring in r.json()['data']['systemDebug'] for substring in systemdebug_indicators)

def test_query_users():
    query = '''
        query {
           users {
               id
               username
           }
        }
    '''

    r = graph_query(GRAPHQL_URL, query)
    assert r.status_code == 200
    assert len(r.json()['data']['users']) > 1

def test_query_users_by_id():
    query = '''
        query {
           users(id: 1) {
               id
               username
           }
        }
    '''

    r = graph_query(GRAPHQL_URL, query)
    assert r.status_code == 200
    assert r.json()['data']['users'][0]['id']
    assert len(r.json()['data']['users']) == 1


def test_query_read_and_burn():
    query = '''
        query {
            readAndBurn(id: 155){
                id
            }
        }
    '''
    r = graph_query(GRAPHQL_URL, query)
    assert r.status_code == 200
    assert r.json()['data']['readAndBurn'] == None

def test_query_search_on_user_object():
    query = '''
        query {
         search(keyword:"operator") {
            ... on UserObject {
                username
                id
              }
          }
        }
    '''

    r = graph_query(GRAPHQL_URL, query)
    assert r.status_code == 200
    assert r.json()['data']['search'][0]['username'] == 'operator'
    assert r.json()['data']['search'][0]['id']


def test_query_search_on_paste_object():
    query = '''
        query {
            search {
                ... on PasteObject {
                owner {
                    name
                    id
                }
                title
                content
                id
                ipAddr
                burn
                ownerId
                }
            }
        }
    '''

    r = graph_query(GRAPHQL_URL, query)
    assert r.status_code == 200
    assert len(r.json()['data']['search']) > 0
    assert r.json()['data']['search'][0]['owner']['id']
    assert r.json()['data']['search'][0]['title']
    assert r.json()['data']['search'][0]['content']
    assert r.json()['data']['search'][0]['id']
    assert r.json()['data']['search'][0]['ipAddr']
    assert r.json()['data']['search'][0]['burn'] == False
    assert r.json()['data']['search'][0]['ownerId']


def test_query_search_on_user_and_paste_object():
    query = '''
        query {
            search(keyword: "p") {
                ... on UserObject {
                    username
                }
                ... on PasteObject {
                    title
                }
            }
        }
    '''
    result = {"username":0, "title":0}

    r = graph_query(GRAPHQL_URL, query)
    assert r.status_code == 200

    for i in r.json()['data']['search']:
        if 'title' in i:
            result['title'] = 1
        elif 'username' in i:
            result['username'] = 1

    assert result['username'] == 1
    assert result['title'] == 1

def test_query_audits():
    query = '''
       query {
            audits {
                id
                gqloperation
                gqlquery
                timestamp
            }
        }
    '''

    r = graph_query(GRAPHQL_URL, query)
    assert r.status_code == 200
    assert len(r.json()['data']['audits']) > 0
    assert r.json()['data']['audits'][0]['id']
    assert r.json()['data']['audits'][0]['gqloperation']
    assert r.json()['data']['audits'][0]['gqlquery']
    assert r.json()['data']['audits'][0]['timestamp']

def test_query_audits():
    query = '''
       query {
            deleteAllPastes
        }
    '''

    r = graph_query(GRAPHQL_URL, query)
    assert r.status_code == 200
    assert r.json()['data']['deleteAllPastes']

    # Rebuild
    r = requests.get(URL + '/start_over')
    assert r.status_code == 200
    #assert 'Restored to default state' in r.text

def test_query_pastes_with_limit():
    query = '''
        query {
            pastes(limit: 2, public: true) {
                content
                title
                owner {
                    name
                }
                ownerId
                userAgent
                public
            }
    }
    '''

    r = graph_query(GRAPHQL_URL, query)
    assert r.status_code == 200
    assert len(r.json()['data']['pastes']) == 2
    assert r.json()['data']['pastes'][0]['content']
    assert r.json()['data']['pastes'][0]['title']
    assert r.json()['data']['pastes'][0]['owner']['name']
    assert r.json()['data']['pastes'][0]['ownerId']
    assert r.json()['data']['pastes'][0]['userAgent']
    assert r.json()['data']['pastes'][0]['public']

def test_query_pastes_with_fragments():
    query = '''
        query {
            pastes {
                ...A
            }
        }

        fragment A on PasteObject {
            content
            title
        }
    '''

    r = graph_query(GRAPHQL_URL, query)
    assert r.status_code == 200
    assert r.json()['data']['pastes'][0]['content']
    assert r.json()['data']['pastes'][0]['title']

def test_check_rollback():
    r = requests.get(URL + '/start_over')
    assert r.status_code == 200
    assert 'Restored to default state' in r.text



def test_circular_query_pastes_owners():
  query = """
    query {
       pastes {
          owner {
              pastes {
                  owner {
                      name
                  }
              }
          }
       }
    }
  """
  r = graph_query(GRAPHQL_URL, query)
  assert r.status_code == 200
  assert r.json()['data']['pastes'][0]['owner']['pastes'][0]['owner']['name'] == 'DVGAUser'

def test_aliases_overloading():
    query = """
        query {
            a1: pastes { id }
            a2: pastes { id }
            a3: pastes { id }
            a4: pastes { id }
            a5: pastes { id }
        }
    """
    r = graph_query(GRAPHQL_URL, query)
    assert r.status_code == 200
    assert len(r.json()['data'].keys()) == 5

def test_field_suggestions():
    query = """
        query {
            systemUpd
        }
    """
    r = graph_query(GRAPHQL_URL, query)
    assert r.status_code == 400
    assert 'Did you mean' in r.json()['errors'][0]['message']

def test_os_injection():
    query = """
        mutation {
            importPaste(host:"hostthatdoesnotexist.com", port:80, path:"/ || id", scheme:"http") {
                result
            }
        }
    """

    r = graph_query(GRAPHQL_URL, query)
    assert r.status_code == 200
    assert 'uid=' in r.json()['data']['importPaste']['result']

def test_os_injection_alt():
    query = """
        query {
            systemDiagnostics(username:"admin", password:"changeme", cmd:"id")
        }
    """

    r= graph_query(GRAPHQL_URL, query)
    assert r.status_code == 200
    assert 'uid=' in r.json()['data']['systemDiagnostics']

def test_xss():
    query = """
        mutation {
            createPaste(title:"<script>alert(1)</script>", content:"zzzz", public:true) {
                paste {
                    title
                }
            }
        }
    """

    r = graph_query(GRAPHQL_URL, query)
    assert r.status_code == 200
    assert r.json()['data']['createPaste']['paste']['title'] == '<script>alert(1)</script>'

def test_log_injection():
    query = """
        query pwned {
            systemHealth
        }
    """

    r = graph_query(GRAPHQL_URL, query)
    assert r.status_code == 200
    r = requests.get(URL + '/audit')

    assert r.status_code == 200
    assert 'query pwned {' in r.text

def test_html_injection():
    query = """
        mutation {
            createPaste(title:"<h1>hello!</h1>", content:"zzzz", public:true) {
                paste {
                    title
                    content
                    public
                }
            }
        }
    """

    r = graph_query(GRAPHQL_URL, query)

    assert r.status_code == 200
    assert r.json()['data']['createPaste']['paste']['title'] == '<h1>hello!</h1>'
    assert r.json()['data']['createPaste']['paste']['content'] == 'zzzz'
    assert r.json()['data']['createPaste']['paste']['public'] == True

def test_sql_injection():
    query = """
        query {
           pastes(filter:"aaa ' or 1=1--") {
                content
                title
            }
        }
    """

    r = graph_query(GRAPHQL_URL, query)
    assert r.status_code == 200
    assert len(r.json()['data']['pastes']) > 1

def test_deny_list_expert_mode():
    query = """
        query {
            systemHealth
        }
    """
    r = graph_query(GRAPHQL_URL, query, headers={"X-DVGA-MODE":'Expert'})
    assert r.status_code == 200
    assert r.json()['errors'][0]['message'] == '400 Bad Request: Query is on the Deny List.'

def test_deny_list_expert_mode_bypass():
    query = """
        query getPastes {
            systemHealth
        }
    """
    r = graph_query(GRAPHQL_URL, query, headers={"X-DVGA-MODE":'Expert'})
    assert r.status_code == 200
    assert 'System Load' in r.json()['data']['systemHealth']
    assert '.' in r.json()['data']['systemHealth'].split('System Load: ')[1]

def test_deny_list_beginner_mode():
    query = """
        query {
            systemHealth
        }
    """
    r = graph_query(GRAPHQL_URL, query, headers={"X-DVGA-MODE":'Beginner'})
    assert r.status_code == 200
    assert 'System Load' in r.json()['data']['systemHealth']
    assert '.' in r.json()['data']['systemHealth'].split('System Load: ')[1]

def test_circular_fragments():
    assert os.path.exists('app.py')
    f = open('app.py', 'r').read()
    assert 'sys.setrecursionlimit(100000)' in f

def test_stack_trace_errors():
    query = """
        query {
            pastes {
                conteeeent
            }
        }
    """
    r = graph_query(GRAPHIQL_URL, query, headers={"X-DVGA-MODE":'Beginner'})
    assert r.status_code == 400
    assert len(r.json()['errors'][0]['extensions']['exception']['stack']) > 0
    assert r.json()['errors'][0]['extensions']['exception']['stack']
    assert 'Traceback' in r.json()['errors'][0]['extensions']['exception']['debug']
    assert r.json()['errors'][0]['extensions']['exception']['path'].endswith('.py')

def test_check_websocket():
    headers = {
        "Connection":"Upgrade",
        "Upgrade":"websocket",
        "Host":"localhost",
        "Origin":"localhost",
        "Sec-WebSocket-Version":"13",
        "Sec-WebSocket-Key":"+onQ3ZxjWlkNa0na6ydhNg=="
    }

    r = requests.get(URL, headers=headers)
    assert r.status_code == 101
    assert r.headers['Upgrade'] == 'websocket'
    assert r.headers['Connection'] == 'Upgrade'
    assert r.headers['Sec-WebSocket-Accept']

