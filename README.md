# API-Security-Crawler

**Requirements to install beforehand** 
GraphQL Visualization: 
- npm install -g graphqlviz
- sudo apt install graphviz or brew install graphviz (source: https://graphviz.org/download/)
To run GraphQL webcrawler: scrapy crawl graphql_spider

To run GraphQL table visualization: 
1. cd graphql/visualization
2. npm install -g graphqlviz
3. python generate_schema_image.py

To run vulnerability scanner: python vuln_scan.py
