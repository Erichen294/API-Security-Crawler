import subprocess
import json
import requests

def fetch_graphql_schema(url, authorization_key=None):
    """Fetches the GraphQL schema via an introspection query."""
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
        }
        """
    }

    headers = {"Content-Type": "application/json"}
    if authorization_key:
        headers["Authorization"] = authorization_key
    response = requests.post(url, json=introspection_query, headers=headers)
    
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Failed to fetch schema, status code: {response.status_code}")
        return None

def save_schema_to_file(schema, filename):
    """Saves the schema to a file."""
    with open(filename, 'w') as file:
        json.dump(schema, file, indent=2)

def execute_graphqlviz(schema_file, output_file):
    """Executes the graphqlviz command to generate a PNG image from a schema file."""
    command = f"graphqlviz {schema_file} --theme.header.invert=true | dot -Tpng > {output_file}"
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()

    if process.returncode == 0:
        print("Graph generated successfully.")
    else:
        print(f"Error generating graph: {stderr.decode()}")

def analyze_schema_for_sensitivity(schema):
    sensitive_keywords = ['password', 'creditCard', 'ssn', 'email']
    sensitive_fields = []

    for type in schema.get("__schema", {}).get("types", []):
        for field in type.get("fields", []):
            if any(keyword in field['name'].lower() for keyword in sensitive_keywords):
                sensitive_fields.append((type['name'], field['name']))

    print("Sensitive fields identified:", sensitive_fields)
    return sensitive_fields

if __name__ == "__main__":
    url = input("Enter the GraphQL endpoint URL: ")
    schema_filename = input("Enter filename to save the schema JSON (e.g., schema.json): ")
    output_image_file = input("Enter output image file name (e.g., schema.png): ")
    schema = fetch_graphql_schema(url)
    if schema:
        save_schema_to_file(schema, schema_filename)
        execute_graphqlviz(schema_filename, output_image_file)
        analyze_schema_for_sensitivity(schema)
    else:
        print("Failed to fetch or validate the GraphQL schema.")

