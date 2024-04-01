import requests
from bs4 import BeautifulSoup

def find_potential_endpoints(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        for script in soup.find_all('script'):
            if 'graphql' in script.get('src', '').lower():
                print(f"Found a <script> tag with a potential GraphQL endpoint: {script['src']}")
                
        for script in soup.find_all('script'):
            if 'graphql' in script.text.lower():
                print("Found inline <script> with a potential GraphQL endpoint mentioned.")

    except requests.RequestException as e:
        print(f"Error fetching {url}: {e}")

url = input("Enter the URL to scan: ")
find_potential_endpoints(url)
