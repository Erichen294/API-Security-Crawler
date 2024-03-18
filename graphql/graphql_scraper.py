import requests
import json

# GRAPHQL schema test to print all schema details from 
# Damn Vulnerable GraphQL Application (DVGA)

GRAPHQL_ENDPOINT = "http://localhost:5000/dvga"

# GraphQL introspection query for retrieving schema information
introspection_query = {
    "query": """
        query IntrospectionQuery {
            __schema {
                types {
                    name
                    kind
                    description
                    fields(includeDeprecated: true) {
                        name
                        description
                    }
                }
            }
        }
    """
}

def get_graphql_schema(endpoint):
    # Send the introspection query to the GraphQL endpoint
    response = requests.post(endpoint, json=introspection_query)
    if response.status_code == 200:
        # Parse the JSON response
        schema_info = response.json()
        # Extract and return the schema details
        return schema_info['data']['__schema']['types']
    else:
        raise Exception(f"Failed to fetch schema, status code: {response.status_code}")

def main():
    try:
        schema_details = get_graphql_schema(GRAPHQL_ENDPOINT)
        print(json.dumps(schema_details, indent=2))
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
