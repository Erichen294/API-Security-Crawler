import scrapy
from scrapy.crawler import CrawlerProcess

class GraphQLSpider(scrapy.Spider):
    name = 'graphql_spider'
    allowed_domains = ['localhost']
    start_urls = ['http://localhost:5013']

    graphql_paths = [
    '/',
    '/graphql',
    '/graphiql',
    '/v1/graphql',
    '/v2/graphql',
    '/v3/graphql',
    '/v1/graphiql',
    '/v2/graphiql',
    '/v3/graphiql',
    '/api/graphql',
    '/api/graphiql',
    '/console',
    '/playground',
    '/gql',
    '/query',
    '/index.php?graphql',
    '/rpc/graphql'
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

if __name__ == "__main__":
    process = CrawlerProcess()
    process.crawl
