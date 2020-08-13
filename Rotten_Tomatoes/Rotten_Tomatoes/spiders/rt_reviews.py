# -*- coding: utf-8 -*-
import scrapy
from scrapy.utils.response import open_in_browser
from scrapy import Request
from scrapy.shell import inspect_response
from scrapy.http import HtmlResponse
from Rotten_Tomatoes.middlewares import driver
from selenium.webdriver.support.wait import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By
from Rotten_Tomatoes.items import RottenTomatoesItem
import logging
import time
from datetime import date, datetime, timedelta
from bson.objectid import ObjectId


class RtReviewsSpider(scrapy.Spider):
    name = 'rt_reviews'
    allowed_domains = ['rottentomatoes.com']
    #start_urls = ['https://www.rottentomatoes.com/m/the_gallows_act_ii/reviews?type=user']

    def __init__(self, url, user_id, project_id, timestamp,  *args, **kwargs):
        super(RtReviewsSpider, self).__init__(*args, **kwargs)
        self.start_urls = [url]
        self.user_id = ObjectId(str(user_id))
        self.project_id = ObjectId(str(project_id))
        if timestamp == 'None':
            self.last_update_date = None
        else:
            timestamp = datetime.strptime(timestamp, "%Y-%m-%d")
            self.last_update_date = timestamp.date()


    def parse(self, response):
        is_last = False
        while True:
            response = HtmlResponse(driver.current_url, body=driver.page_source, encoding='utf-8')
            # open_in_browser(response)
            # inspect_response(response, self)
            logging.log(logging.INFO, "Parsing all reviews section!!!")

            for review_li in response.xpath("//ul[@class='audience-reviews']").xpath("./child::li"):
                if self.last_update_date is not None:
                    temp_item = self.parse_review(review_li)
                    #temp_item['review_date'].date() > self.last_update_date
                    if True:
                        yield temp_item
                    else:
                        logging.log(logging.INFO, "Scraped new data...")
                        driver.close()
                        return

                else:
                    yield self.parse_review(review_li)

            if is_last == True:
                break
            logging.warning("1- next-element-class-text: "+driver.find_element_by_xpath('//button[@data-direction="next"]').get_attribute('class'))
            web_element = WebDriverWait(driver, 20)\
                .until(EC.presence_of_element_located((By.XPATH, '//button[@data-direction="next"]')))

            web_element.location_once_scrolled_into_view
            try:
                web_element.click()
            except:
                pass
            logging.warning("2- next-element-class-text: "+web_element.get_attribute('class'))
            if 'hide' in web_element.get_attribute('class'):
                is_last = True

            '''
            driver.find_element_by_xpath('//button[@data-direction="next"]').click()
            time.sleep(2)
            if 'hide' in driver.find_element_by_xpath('//button[@data-direction="next"]').get_attribute('class'):
                is_last = True
            '''
        logging.log(logging.INFO, "Alhamad u lillah, Scraped all pages successfully!!!")
        # time.sleep(20)
        driver.close()
        '''try:
            
        except:
            logging.log(logging.WARNING, "Exception occurred, selenium driver is closing...")
            driver.close()'''

    def parse_review(self, review_li):
        try:
            # logging.log(logging.INFO, review_li)
            logging.log(logging.INFO, "Parsing single review section")
            RTItem = RottenTomatoesItem()

            RTItem['user_id'] = self.user_id
            RTItem['project_id'] = self.project_id
            if review_li.xpath(".//img[contains(@class, 'image-avatar')]/@src") is not None:
                if len(review_li.xpath(".//img[contains(@class, 'image-avatar')]/@src")) > 0:
                    temp_img = review_li.xpath(".//img[contains(@class, 'image-avatar')]/@src").extract_first()
                    if temp_img is not None:
                        RTItem['user_picture'] = temp_img
                    else:
                        RTItem['user_picture'] = 'https://gooddonegreat.com/app/img/placeholders/avatar-150x150.png'
                else:
                    RTItem['user_picture'] = 'https://gooddonegreat.com/app/img/placeholders/avatar-150x150.png'
            else:
                RTItem['user_picture'] = 'https://gooddonegreat.com/app/img/placeholders/avatar-150x150.png'
            if review_li.xpath(".//*[contains(@class, 'reviews__name')]/text()") is not None:
                if review_li.xpath(".//*[contains(@class, 'reviews__name')]/text()").extract_first() is not None:
                    temp = review_li.xpath(".//*[contains(@class, 'reviews__name')]/text()").extract()
                    temp_name = ' '.join(temp)
                    temp_name = temp_name.strip()
                    RTItem['user_name'] = temp_name
                else:
                    RTItem['user_name'] = "Unknown"
            else:
                RTItem['user_name'] = "Unknown"
            if review_li.xpath(".//span[contains(@class, 'reviews__duration')]/text()").extract_first() is not None:
                date_extracted = review_li.xpath(
                    ".//span[contains(@class, 'reviews__duration')]/text()").extract_first().strip()

                if 'h' in date_extracted and 'ago' in date_extracted:
                    actual_date = date.today().strftime("%b %d, %Y")
                elif 'm' in date_extracted and 'ago' in date_extracted:
                    actual_date = date.today().strftime("%b %d, %Y")
                elif 'd' in date_extracted and 'ago' in date_extracted:
                    temp_date = datetime.now() - timedelta(int(date_extracted.split('d')[0]))
                    actual_date = temp_date.strftime("%b %d, %Y")
                else:
                    actual_date = date_extracted

                actual_date = datetime.strptime(actual_date, "%b %d, %Y")
                RTItem['review_date'] = actual_date
            if review_li.xpath(".//p[contains(@class, 'review-text')]/text()").extract_first() is not None:
                RTItem['review_data'] = review_li.xpath(
                    ".//p[contains(@class, 'review-text')]/text()").extract_first().strip()
            return RTItem
        except:
            pass


