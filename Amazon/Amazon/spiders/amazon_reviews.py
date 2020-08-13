# -*- coding: utf-8 -*-
import scrapy
from scrapy.utils.response import open_in_browser
from scrapy.shell import inspect_response
from Amazon.middlewares import driver
from Amazon.items import AmazonItem
import logging
from datetime import datetime
from bson.objectid import ObjectId
from scrapy.utils.project import get_project_settings
from scrapy.crawler import CrawlerProcess



class AmazonReviewsSpider(scrapy.Spider):
    name = 'amazon_reviews'
    allowed_domains = ['amazon.com']

    def __init__(self, url, user_id, project_id, timestamp,  *args, **kwargs):
        super(AmazonReviewsSpider, self).__init__(*args, **kwargs)
        self.start_urls = [url]
        self.user_id = ObjectId(str(user_id))
        self.project_id = ObjectId(str(project_id))
        if timestamp == 'None':
            self.last_update_date = None
        else:
            timestamp = datetime.strptime(timestamp, "%Y-%m-%d")
            self.last_update_date = timestamp.date()


    def parse(self, response):
        #open_in_browser(response)
        #inspect_response(response, self)
        logging.log(logging.INFO, "Good before parsing!!")

        for review_div in response.xpath("//div[@id='cm_cr-review_list']").xpath(
                "child::div[@class='a-section review aok-relative']"):

            if self.last_update_date is not None:
                date_location = review_div.xpath(".//span[contains(@class, 'review-date')]/text()").extract()[0].strip()
                date = ' '.join(date_location.split()[-3:])
                date = datetime.strptime(date, "%B %d, %Y").date()
                #date > self.last_update_date
                if True:
                    yield self.parse_review(review_div)
                else:
                    logging.log(logging.INFO, "Scraped all new data....")
                    driver.close()
                    return
            else:
                yield self.parse_review(review_div)

        if 'disabled' not in response.xpath("//div[@id='cm_cr-review_list']").xpath(".//li[contains(@class, 'a-last')]/@class").extract_first():
            next_page = response.xpath("//div[@id='cm_cr-review_list']").xpath(".//li[contains(@class, 'a-last')]/a/@href").extract_first()
            yield scrapy.Request('https://www.amazon.com/'+next_page, dont_filter=True, callback=self.parse)
        else:
            logging.log(logging.INFO, "Closing gecko driver!")
            driver.close()


    def parse_review(self, review_div):
        logging.log(logging.INFO, "Parsing a review!!!")
        amazon_item = AmazonItem()
        try:
            amazon_item['user_picture'] = \
            review_div.xpath(".//div[@class = 'a-profile-avatar']/img/@data-src").extract()[0]
            amazon_item['user_name'] = review_div.xpath(".//div[@class = 'a-profile-content']/span/text()").extract()[0]
            amazon_item['review_title'] = review_div.xpath(".//div[@class = 'a-row']").xpath(
                ".//a[contains(@class, 'review-title-content')]/span/text()").extract()[0]

            amazon_item['review_date'] = review_div.xpath(".//span[contains(@class, 'review-date')]/text()").extract()[
                0].strip()
            # logging.warning("review_date: ", amazon_item['review_date'])
            amazon_item['review_date'] = ' '.join(amazon_item['review_date'].split()[-3:])
            amazon_item['review_date'] = datetime.strptime(amazon_item['review_date'], "%B %d, %Y")
            amazon_item['review_data'] = ' '.join(
                review_div.xpath(".//span[@class='a-size-base review-text review-text-content']/span/text()").extract())
            amazon_item['user_id'] = self.user_id
            amazon_item['project_id'] = self.project_id
            return amazon_item
        except:
            pass
