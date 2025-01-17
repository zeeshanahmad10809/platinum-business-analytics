# -*- coding: utf-8 -*-

# Define here the models for your spider middleware
#
# See documentation in:
# https://doc.scrapy.org/en/latest/topics/spider-middleware.html

from scrapy import signals
from scrapy.http import HtmlResponse
from selenium import webdriver
from selenium.webdriver.firefox.options import Options
import logging
import requests
from PIL import Image
from io import BytesIO
import pytesseract


options = Options()
options.headless = False
driver = webdriver.Firefox(executable_path="../geckodriver")


class AmazonSpiderMiddleware(object):
    # Not all methods need to be defined. If a method is not defined,
    # scrapy acts as if the spider middleware does not modify the
    # passed objects.

    @classmethod
    def from_crawler(cls, crawler):
        # This method is used by Scrapy to create your spiders.
        s = cls()
        crawler.signals.connect(s.spider_opened, signal=signals.spider_opened)
        return s

    def process_spider_input(self, response, spider):
        # Called for each response that goes through the spider
        # middleware and into the spider.

        # Should return None or raise an exception.
        return None

    def process_spider_output(self, response, result, spider):
        # Called with the results returned from the Spider, after
        # it has processed the response.

        # Must return an iterable of Request, dict or Item objects.
        for i in result:
            yield i

    def process_spider_exception(self, response, exception, spider):
        # Called when a spider or process_spider_input() method
        # (from other spider middleware) raises an exception.

        # Should return either None or an iterable of Response, dict
        # or Item objects.
        pass

    def process_start_requests(self, start_requests, spider):
        # Called with the start requests of the spider, and works
        # similarly to the process_spider_output() method, except
        # that it doesn’t have a response associated.

        # Must return only requests (not items).
        for r in start_requests:
            yield r

    def spider_opened(self, spider):
        spider.logger.info("Spider opened: %s" % spider.name)


class AmazonDownloaderMiddleware(object):
    # Not all methods need to be defined. If a method is not defined,
    # scrapy acts as if the downloader middleware does not modify the
    # passed objects.

    @classmethod
    def from_crawler(cls, crawler):
        # This method is used by Scrapy to create your spiders.
        s = cls()
        crawler.signals.connect(s.spider_opened, signal=signals.spider_opened)
        return s

    def process_request(self, request, spider):
        # Called for each request that goes through the downloader
        # middleware.

        # Must either:
        # - return None: continue processing this request
        # - or return a Response object
        # - or return a Request object
        # - or raise IgnoreRequest: process_exception() methods of
        #   installed downloader middleware will be called

        logging.log(logging.INFO, "Entered Download Middleware process_request")
        if "amazon.com" in request.url and "reviewerType=all_reviews" in request.url:
            driver.get(request.url)

            while True:
                if (
                    driver.find_element_by_xpath("//title").get_attribute("innerText")
                    == "Robot Check"
                ):
                    logging.log(logging.INFO, "Checking Captcha!")
                    link = (
                        driver.find_element_by_xpath('//div[@class="a-section"]')
                        .find_element_by_xpath(".//img")
                        .get_attribute("src")
                    )
                    solved_captcha = self.captcha_solver(link)
                    logging.log(logging.INFO, "Solved captcha: " + solved_captcha)

                    driver.find_element_by_xpath(
                        "//input[@class='a-span12']"
                    ).send_keys(solved_captcha)
                    driver.find_element_by_xpath("//button[@type='submit']").click()

                else:
                    body = driver.page_source
                    return HtmlResponse(
                        driver.current_url, body=body, encoding="utf-8", request=request
                    )

        return None

    def captcha_solver(self, captcha_url):
        captcha_response = requests.get(captcha_url)
        img = Image.open(BytesIO(captcha_response.content))
        captcha = pytesseract.image_to_string(img)
        logging.log(logging.INFO, str("Captcha Solved: " + captcha))
        return captcha

    def process_response(self, request, response, spider):
        # Called with the response returned from the downloader.

        # Must either;
        # - return a Response object
        # - return a Request object
        # - or raise IgnoreRequest
        return response

    def process_exception(self, request, exception, spider):
        # Called when a download handler or a process_request()
        # (from other downloader middleware) raises an exception.

        # Must either:
        # - return None: continue processing this exception
        # - return a Response object: stops process_exception() chain
        # - return a Request object: stops process_exception() chain
        pass

    def spider_opened(self, spider):
        spider.logger.info("Spider opened: %s" % spider.name)
