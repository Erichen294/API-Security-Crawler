import scrapy
from scrapy.linkextractors import LinkExtractor
from scrapy.spiders import CrawlSpider, Rule
from scrapy.loader import ItemLoader
from web_scraper.items import Article
from scrapy.http import HtmlResponse
import re
import json

def process_value(value):
    match = re.search(r'\d+/\d+/\d+/(.+)/', value)
    if not match:
        return None

    slug = match.group(1)
    api_pattern = 'https://techcrunch.com/wp-json/wp/v2/posts?slug={}'
    return api_pattern.format(slug)

class TechcrunchSpider(CrawlSpider):
    name = "techcrunch"
    allowed_domains = ["techcrunch.com"]
    start_urls = ["https://techcrunch.com"]

    rules = (
        Rule(
            LinkExtractor(
                allow_domains=allowed_domains,
                process_value=process_value
            ),
            callback='parse_item',
            follow = True
        ),
    )

    # rules = (
    # Rule(
    #     LinkExtractor(
    #         allow=r'\d+/\d+/\d+/.+/',
    #     ),
    #     callback='parse_item',
    #     follow = True
    # ),
    # )

    def parse_item(self, response):
        # item = {}
        # #item["domain_id"] = response.xpath('//input[@id="sid"]/@value').get()
        # #item["name"] = response.xpath('//div[@id="name"]').get()
        # #item["description"] = response.xpath('//div[@id="description"]').get()
        # return item
    
        json_res = json.loads(response.body)
        if not isinstance(json_res, list) or len(json_res) < 1:
            return None

        data = json_res[0]
        content = HtmlResponse(
            response.url,
            body=bytes(data['content']['rendered'], 'utf-8')
        )

        loader = ItemLoader(item=Article(), response=content)
        loader.add_value('title', data['title']['rendered'])
        loader.add_value('publish_date', data['date_gmt'])

        loader.add_css('content', '*::text')
        loader.add_css('image_urls', 'img::attr(src)')
        loader.add_css('links', 'a::attr(href)')
        return loader.load_item()
