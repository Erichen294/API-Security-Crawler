# API-Security-Crawler GraphQL Instructions

**Description**

GraphQL is a query language for APIs that allows clients to request only the data they need. The scanner detects various vulnerabilities including sensitive data exposure, unauthorized field access, injection attacks, denial of service attacks, and more. It covers a range of potential security risks within GraphQL APIs.

**Requirements to install beforehand** 
- GraphQL Visualization: 
  - npm install -g graphqlviz
  - sudo apt install graphviz or brew install graphviz (source: https://graphviz.org/download/)

- Tester websites: Navigate to folder tester websites to see read me for each individual website.

- Python installations:
  - pip install requests
  - pip install scrapy 

**To run GraphQL vulnerability scanner once installation is finished:**
- cd .\graphql\graphql_finder\graphql_finder\spiders\
- python GQLCrawl.py
