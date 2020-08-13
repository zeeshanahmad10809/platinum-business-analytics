# -*- coding: utf-8 -*-
import scrapy
#install google for googlesearch
from googlesearch import search
import re
from datetime import datetime, timedelta
from random import randrange
from bson.objectid import ObjectId
import operator
import logging
#from articleDateExtractor import getMyName
from Google.items import GoogleItem


class GoogleResultsSpider(scrapy.Spider):
    name = 'google_results'

    def __init__(self, query, user_id, project_id, timestamp,  *args, **kwargs):
        super(GoogleResultsSpider, self).__init__(*args, **kwargs)
        urls=[]
        '''if last_day == True:
            #for url in search(query, tbs='qdr:d'):
            for url in search(query):
                logging.warning("collecting url: ", url)
                urls.append(url)
        else:
            for url in search(query):
                urls.append(url)'''
        #A simple first search(query)  is replaced now with condition and for both cases this time...
        if timestamp == 'None':
            self.last_update_date = None
            logging.log(logging.INFO, "Searching for all time google search results....")
            for url in search(query):
                urls.append(url)
        else:
            timestamp = datetime.strptime(timestamp, "%Y-%m-%d")
            self.last_update_date = timestamp.date()
            logging.log(logging.INFO, "Searching for last week google search results only....")
            for url in search(query, tbs='qdr:w'):
                urls.append(url)

        self.start_urls = urls
        if len(self.start_urls) == 0:
            raise Exception

        logging.info("Google result urls has been collected!!!")
        self.query = query.lower()
        self.user_id = ObjectId(str(user_id))
        self.project_id = ObjectId(str(project_id))


    def parse(self, response):
        try:
            created_date = self.extractDateCreated(response)
            # This has been below 3 three lines...
            if self.last_update_date is not None:
                # Here it should be less or equal or only less...?
                if created_date.date() <= self.last_update_date:
                    logging.log(logging.INFO, "Skiping scraping google search url because of outdated...")
                    return
            category = self.extractCategory(response)
            if response.xpath("//title/text()") is not None:
                title = response.xpath("//title/text()").extract()[0].strip()
            results = response.xpath(
                "//p[contains(translate(text(), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), '" + self.query + "')]") + \
                      response.xpath(
                          "//span[contains(translate(text(), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), '" + self.query + "')]") + \
                      response.xpath(
                          "//h1[contains(translate(text(), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), '" + self.query + "')]")

            mentions = ''
            for mention_tag in results:
                mention_text = mention_tag.xpath("./text()").extract()[0].strip()
                if len(mention_text.split()) > 0:
                    mentions = mentions + mention_text + '[**break**]'
            mentions = mentions[:-11]
            mentions = re.sub('\t+', ' ', mentions)
            mentions = re.sub('\n+', ' ', mentions)
            mentions = re.sub(' +', ' ', mentions)

            googleItem = GoogleItem()
            googleItem['site_url'] = response.url
            googleItem['site_title'] = title
            googleItem['mention_text'] = mentions
            googleItem['mention_category'] = category
            googleItem['publish_date'] = created_date
            googleItem['user_id'] = self.user_id
            googleItem['project_id'] = self.project_id

            logging.warning("url: " + str(response.url))
            logging.warning("Created: " + str(created_date))
            logging.warning("Category: " + str(category))
            logging.warning("Mentions: " + str(mentions))
            return googleItem
        except:
            pass






    def extractDateCreated(self, response):
        def get_random_date():
            random_day = randrange(10)
            date_N_days_ago = datetime.now() - timedelta(days=random_day)
            return date_N_days_ago

        try:
            results = response.xpath(
                "//meta[re:match(@content, '(\d{4}|\d{2})-(\d{2}|\d{1})-(\d{2}|\d{1})')]|//time[re:match(@datetime, '(\d{4}|\d{2})-(\d{2}|\d{1})-(\d{2}|\d{1})')]")
            if len(results) > 0:
                extracted_date = results[0].xpath("./@content").extract()[0]
                match_date = re.match('(\d{4}|\d{2})-(\d{2}|\d{1})-(\d{2}|\d{1})', extracted_date)
                if match_date is not None:
                    text_date = match_date.group()
                    actual_date = datetime.strptime(text_date, '%Y-%m-%d')
                else:
                    actual_date = get_random_date()
                return actual_date
            else:
                return get_random_date()
        except:
            return get_random_date()

    def extractCategory(self, response):
        def get_translation(keyword):
            translation_table = keyword.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')
            translated_keyword = keyword.translate(translation_table)
            return translated_keyword

        def check_keywords(target, votes):
            for keyword in news_keywords:
                if keyword in target:
                    votes['news'] = votes['news'] + 1

            for keyword in blog_keywords:
                if keyword in target:
                    votes['blog'] = votes['blog'] + 1

            for keyword in podcast_keywords:
                if keyword in target:
                    votes['podcast'] = votes['podcast'] + 1
            return votes

        votes = dict()
        votes['news'] = 0
        votes['blog'] = 0
        votes['podcast'] = 0

        news_keywords = ['news', 'newspaper', 'newspapers']
        blog_keywords = ['blog', 'blogging', 'blogger', 'bloggers', 'blogs']
        podcast_keywords = ['podcast', 'podcasts']

        #url to check keywords...
        url = response.url
        url = get_translation(url)
        votes = check_keywords(url, votes)

        #check web-page's keywords to match keywords...
        if response.xpath("//meta[@name='keywords']/@content") is not None and len(response.xpath("//meta[@name='keywords']/@content")) > 0:
            web_page_keywords = response.xpath("//meta[@name='keywords']/@content")[0].extract()
            web_page_keywords = get_translation(web_page_keywords)
            votes = check_keywords(web_page_keywords, votes)

        #check description tag to match keywords...
        if response.xpath("//meta[@name='description']/@content") is not None and len(response.xpath("//meta[@name='description']/@content")) > 0:
            description = response.xpath("//meta[@name='description']/@content")[0].extract()
            description = get_translation(description)
            votes = check_keywords(description, votes)


        max_tuple =  max(votes.items(), key=operator.itemgetter(1))
        if max_tuple[1] > 0:
            return max_tuple[0]
        else:
            return 'web'



