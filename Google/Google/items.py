# -*- coding: utf-8 -*-

# Define here the models for your scraped items
#
# See documentation in:
# https://docs.scrapy.org/en/latest/topics/items.html

import scrapy


class GoogleItem(scrapy.Item):
    # define the fields for your item here like:
    # name = scrapy.Field()
    site_url = scrapy.Field()
    site_title = scrapy.Field()
    mention_text = scrapy.Field()
    mention_category = scrapy.Field()
    mention_sentiment = scrapy.Field()
    publish_date = scrapy.Field()
    user_id = scrapy.Field()
    project_id = scrapy.Field()
