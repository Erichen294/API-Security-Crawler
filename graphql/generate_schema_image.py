import requests
import json
import graphviz

def fetch_graphql_schema(url):
    # Define the GraphQL introspection query
    introspection_query = {
        "query": """query IntrospectionQuery {
          __schema {
            queryType { name }
            mutationType { name }
            subscriptionType { name }
            types {
              ...FullType
            }
            directives {
              name
              description
              locations
              args {
                ...InputValue
              }
            }
          }
        }
        fragment FullType on __Type {
          kind
          name
          description
          fields(includeDeprecated: true) {
            name
            description
            args {
              ...InputValue
            }
            type {
              ...TypeRef
            }
            isDeprecated
            deprecationReason
          }
          inputFields {
            ...InputValue
          }
          interfaces {
            ...TypeRef
          }
          enumValues(includeDeprecated: true) {
            name
            description
            isDeprecated
            deprecationReason
          }
          possibleTypes {
            ...TypeRef
          }
        }
        fragment InputValue on __InputValue {
          name
          description
          type { ...TypeRef }
          defaultValue
        }
        fragment TypeRef on __Type {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
                ofType {
                  kind
                  name
                  ofType {
                    kind
                    name
                    ofType {
                      kind
                      name
                      ofType {
                        kind
                        name
                      }
                    }
                  }
                }
              }
            }
          }
        }"""
    }
    
    headers = {"Content-Type": "application/json"}
    response = requests.post(url, json=introspection_query, headers=headers)
    
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Failed to fetch schema, status code: {response.status_code}")
        return None

def print_graphql_type_tables(schema_data):
    # Iterate over all types in the schema
    for graphql_type in schema_data.get('__schema', {}).get('types', []):
        if graphql_type['name'].startswith('__'):
            continue
        
        print(f"{graphql_type['name']}")
        print('=' * len(graphql_type['name']))
        
        # Check if the type has fields (OBJECT, INTERFACE)
        fields = graphql_type.get('fields')
        if fields:
            for field in fields:
                field_name = field['name']
                field_type = get_field_type(field['type'])
                args = [arg['name'] for arg in field.get('args', [])]
                args_str = ', '.join(args) if args else 'No arguments'
                print(f"{field_name} ({field_type}) - {args_str}")
        else:
            print('No fields')
        
        print()  

def get_field_type(field_type):
    # Recursively get the name of the type (OBJECT, SCALAR, ENUM, etc.)
    if field_type.get('ofType'):
        return get_field_type(field_type.get('ofType'))
    else:
        return field_type.get('name')
    
def save_schema_to_file(schema, filename):
    with open(filename, 'w') as file:
        json.dump(schema, file, indent=2)

def load_schema_from_file(filename):
    with open(filename, 'r') as file:
        return json.load(file)

if __name__ == "__main__":
    url = input("Enter the GraphQL endpoint URL: ")
    schema = fetch_graphql_schema(url)
    if schema:
        schema_file = "schema.json"  
        save_schema_to_file(schema, schema_file)
        
        schema_data = load_schema_from_file(schema_file)
        
        print_graphql_type_tables(schema_data['data'])

        print("The GraphQL schema types have been printed.")
    else:
        print("Failed to fetch or validate the GraphQL schema.")
