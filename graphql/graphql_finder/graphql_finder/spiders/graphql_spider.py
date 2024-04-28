import scrapy
from scrapy.crawler import CrawlerProcess
import json

class GraphQLSpider(scrapy.Spider):
    def __init__(self, start_urls=None, authorization_key=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.start_urls = start_urls
        self.authorization_key = authorization_key

    name = 'graphql_spider'
    allowed_domains = ['localhost']

    graphql_paths = [
        '/',
        '/altair',
        '/explorer',
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


    def start_requests(self):
        headers = {'Content-Type': 'application/json'}
        if self.authorization_key:
            headers['Authorization'] = self.authorization_key

        for end in self.graphql_paths:
            for start_url in self.start_urls:
                url = start_url + end
                yield scrapy.Request(
                    url=url,
                    method='POST',
                    headers=headers,
                    body=json.dumps({'query': '{ __schema { types { name } } }'}),
                    callback=self.parse_graphql_response
                )

    def parse_graphql_response(self, response):
        if response.status == 200:
            with open("valid_endpoints.json", "w") as file:
                json.dump({'url': response.url}, file)
                file.write('\n') 
            self.log(f"GraphQL API response saved: {response.url}")
        else:
            self.log(f"GraphQL endpoint does not exist")

    def log(self, message):
        self.logger.info(message)

# if __name__ == "__main__":
#     process = CrawlerProcess()
#     process.crawl(GraphQLSpider)
#     process.start()
