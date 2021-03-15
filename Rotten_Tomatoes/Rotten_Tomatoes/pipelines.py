# -*- coding: utf-8 -*-

# Define your item pipelines here
#
# Don't forget to add your pipeline to the ITEM_PIPELINES setting
# See: https://doc.scrapy.org/en/latest/topics/item-pipeline.html
import pymongo
import logging
import requests
import os
import json
from bson.objectid import ObjectId
from textblob import TextBlob
from langdetect import detect


class RottenTomatoesPipeline(object):
    def __init__(self):
        client = pymongo.MongoClient("localhost", 27017)
        SocialBird = client["PlatinumBusinessAnalytics"]
        self.ProjectData = SocialBird["ProjectData"]
        logging.log(logging.INFO, "Docuement Created Succeessfully!")

    def process_item(self, item, spider):
        # b = TextBlob(item['review_data'])
        # if b.detect_language() != 'en':
        #   return item
        if detect(item["review_data"]) != "en":
            return item

        logging.warning("This is a english review")
        r = requests.get(
            "http://127.0.0.1:5000/get_sentiment/", params={"text": item["review_data"]}
        )
        if r.status_code == 200:
            item["review_sentiment"] = r.json()["Sentiment"]
        else:
            item["review_sentiment"] = 2

        # item['review_sentiment'] = 1
        logging.warning("This is sentiment " + str(item["review_sentiment"]))
        # self.temp_doc.insert_one(dict(item))
        self.ProjectData.update(
            {"_id": item["user_id"], "projects._id": item["project_id"]},
            {
                "$push": {
                    "projects.$.data": {
                        "user_picture": item["user_picture"],
                        "user_name": item["user_name"],
                        "review_id": ObjectId(),
                        "review_date": item["review_date"],
                        "review_data": item["review_data"],
                        "seen": False,
                        "review_sentiment": item["review_sentiment"],
                    }
                }
            },
        )
        return item
