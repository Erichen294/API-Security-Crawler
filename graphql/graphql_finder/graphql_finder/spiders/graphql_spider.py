import scrapy
from scrapy.crawler import CrawlerProcess
import json

class GraphQLSpider(scrapy.Spider):
    name = 'graphql_spider'
    allowed_domains = ['localhost']
    start_urls = ['http://127.0.0.1:31337/']

    graphql_paths = [
        '/',
        '/altair',
        '/explorer',
        '/graphiql',
        '/graph',
        '/graphql',
        '/graphql/console',
        '/graphql-explorer',
        '/playground',
        '/subscriptions',
        '/api/graphql',
        '/api/graphiql',
        '/console',
        '/gql',
        '/query',
        '/index.php?graphql',
        '/rpc/graphql',
        '/api/v1/graphql',
        '/services/graphql',
        '/data/graphql',
        '/gql/api',
        '/dev/graphql',
        '/gql/query',
        '/api/data/graphql',
        '/services/gql',
        '/admin/graphql',
        '/secure/graphql',
    
        # Version 1 specific paths
        '/v1/altair',
        '/v1/explorer',
        '/v1/graphiql',
        '/v1/graphql',
        '/v1/graphql/console',
        '/v1/graphql-explorer',
        '/v1/playground',
        '/v1/subscriptions',
        '/v1/graph',
    
        # Version 2 specific paths
        '/v2/altair',
        '/v2/explorer',
        '/v2/graphiql',
        '/v2/graphql',
        '/v2/graphql/console',
        '/v2/graphql-explorer',
        '/v2/playground',
        '/v2/subscriptions',
        '/v2/graph',
    
        # Version 3 specific paths
        '/v3/altair',
        '/v3/explorer',
        '/v3/graphiql',
        '/v3/graphql',
        '/v3/graphql/console',
        '/v3/graphql-explorer',
        '/v3/playground',
        '/v3/subscriptions',
        '/v3/graph',
    
        # Version 4 specific paths
        '/v4/altair',
        '/v4/explorer',
        '/v4/graphiql',
        '/v4/graphql',
        '/v4/graphql/console',
        '/v4/graphql-explorer',
        '/v4/playground',
        '/v4/subscriptions',
        '/v4/graph'
    ]


    def parse(self, response):
        # Process inline and external script tags for GraphQL endpoint clues
        scripts = response.xpath("//script").extract()
        for script_content in scripts:
            if 'graphql' in script_content.lower():
                self.log_red(f"Possible GraphQL data in script: {script_content[:100]}")

        # Process <a> tags for links to API documentation or GraphQL IDEs
        links = response.xpath("//a[contains(., 'API') or contains(., 'GraphQL')]/@href").extract()
        for link in links:
            yield response.follow(link, callback=self.parse)

        # Append possible GraphQL paths to each new path found and check those URLs
        for href in response.css('a::attr(href)').getall():
            base_url = response.urljoin(href)
            if "localhost" in base_url:  # Directly check for 'localhost' in base_url
                for path in self.graphql_paths:
                    full_url = base_url.rstrip('/') + path
                    yield scrapy.Request(full_url, callback=self.check_graphql_endpoint, meta={'handle_httpstatus_list': [404]})

    def check_graphql_endpoint(self, response):
        if response.status == 404:
            return
        self.log_red(f"Checked GraphQL endpoint: {response.url} - Status: {response.status}")

    def log_red(self, message):
        RED_START = '\033[91m'
        RED_END = '\033[0m'
        print(f"{RED_START}{message}{RED_END}")
        self.logger.info(message)  

    # add into a valid endpoints into a file
    def check_graphql_endpoint(self, response):
        if response.status != 404:
            # Save the valid endpoint to a file
            with open("valid_endpoints.json", "a") as file:
                json.dump({'url': response.url}, file)
                file.write('\n')  # for new line
            self.log_red(f"Checked GraphQL endpoint: {response.url} - Status: {response.status}")



if __name__ == "__main__":
    process = CrawlerProcess()
    process.crawl(GraphQLSpider)
    process.start()


# import scrapy
# from scrapy.crawler import CrawlerProcess
# import json

# class AuthenticateSpider(scrapy.Spider):
#     name = 'saleor_graphql_spider'
#     allowed_domains = ['localhost']
#     start_urls = ['http://localhost:8000/']

#     graphql_paths = [
#         '/',
#         '/altair',
#         '/explorer',
#         '/graphiql',
#         '/graph',
#         '/graphql',
#         '/graphql/console',
#         '/graphql-explorer',
#         '/playground',
#         '/subscriptions',
#         '/api/graphql',
#         '/api/graphiql',
#         '/console',
#         '/gql',
#         '/query',
#         '/index.php?graphql',
#         '/rpc/graphql',
#         '/api/v1/graphql',
#         '/services/graphql',
#         '/data/graphql',
#         '/gql/api',
#         '/dev/graphql',
#         '/gql/query',
#         '/api/data/graphql',
#         '/services/gql',
#         '/admin/graphql',
#         '/secure/graphql',

#         # Version 1 specific paths
#         '/v1/altair',
#         '/v1/explorer',
#         '/v1/graphiql',
#         '/v1/graphql',
#         '/v1/graphql/console',
#         '/v1/graphql-explorer',
#         '/v1/playground',
#         '/v1/subscriptions',
#         '/v1/graph',

#         # Version 2 specific paths
#         '/v2/altair',
#         '/v2/explorer',
#         '/v2/graphiql',
#         '/v2/graphql',
#         '/v2/graphql/console',
#         '/v2/graphql-explorer',
#         '/v2/playground',
#         '/v2/subscriptions',
#         '/v2/graph',

#         # Version 3 specific paths
#         '/v3/altair',
#         '/v3/explorer',
#         '/v3/graphiql',
#         '/v3/graphql',
#         '/v3/graphql/console',
#         '/v3/graphql-explorer',
#         '/v3/playground',
#         '/v3/subscriptions',
#         '/v3/graph',

#         # Version 4 specific paths
#         '/v4/altair',
#         '/v4/explorer',
#         '/v4/graphiql',
#         '/v4/graphql',
#         '/v4/graphql/console',
#         '/v4/graphql-explorer',
#         '/v4/playground',
#         '/v4/subscriptions',
#         '/v4/graph'
#     ]
    
#     def start_requests(self):
#         headers = {
#             'Content-Type': 'application/json',
#             'Authorization': 'eyJhbGciOiJSUzI1NiIsImtpZCI6ImpVcFZZYjI1ZHRlVUZYeWljLU56S3lldjhVSjI0T002Mjg1TGo5OFdCbFEiLCJ0eXAiOiJKV1QifQ.eyJpYXQiOjE3MTM4ODQ2OTYsIm93bmVyIjoic2FsZW9yIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDAwL2dyYXBocWwvIiwiZXhwIjoxNzEzODg0OTk2LCJ0b2tlbiI6InNqVFp2RkRIUmgwWSIsImVtYWlsIjoiYWRtaW5AZXhhbXBsZS5jb20iLCJ0eXBlIjoiYWNjZXNzIiwidXNlcl9pZCI6IlZYTmxjam8zTVE9PSIsImlzX3N0YWZmIjp0cnVlfQ.fkgNQoTpZU_f4TXAEy4-GnbdxzTqKVFJf6M2hGRH716vpeniW2vr0RlYMglRdAMpuBoYcsWJ5gKbUBMfqVYhwzY57yi8P8RAUBuij-fH0nl_KmgCQB0P43T6rv9m6IzU-IIEzHcAHZThe5bIV3DuynJdBW43X7_eZh3v5rLysAy-aUnRCsomZOc0p2g2QtAebDBCxeipbPH86MiAEUs0MUZg_ptJXbkXFqqI3yJE6saK5BrLqO1_wWUgM82RB921khsUgKDtHTrg0Mm_Eq7c8jwCHGPRpQthWEZhxVb6KKPwxr-0z5wlqo8pgNtfGjP_P6ydnI0Kn-_FslEFS2W31g',  # Replace YOUR_TOKEN_HERE with your actual token
#         }

#         for end in self.graphql_paths:
#             url = 'http://localhost:8000' + end + '/'
#             yield scrapy.Request(
#                 url=url,
#                 method='POST',
#                 headers=headers,
#                 body=json.dumps({'query': '{ __schema { types { name } } }'}),  # Sample query
#                 callback=self.parse_graphql_response
#             )

#     def parse_graphql_response(self, response):
#         if response.status == 200:
#             with open("valid_endpoints.json", "w") as file:
#                 json.dump({'url': response.url}, file)
#                 file.write('\n') 
#             self.log(f"GraphQL API response saved: {response.url}")
#         else:
#             self.log(f"GraphQL endpoint does not exist")

#     def log(self, message):
#         self.logger.info(message)

# if __name__ == "__main__":
#     process = CrawlerProcess()
#     process.crawl(AuthenticateSpider)
#     process.start()
