# -*- coding: utf-8 -*-

# Define your item pipelines here
#
# Don't forget to add your pipeline to the ITEM_PIPELINES setting
# See: https://docs.scrapy.org/en/latest/topics/item-pipeline.html
import pymongo
import logging
import requests
import os
import json
from bson.objectid import ObjectId
from textblob import TextBlob
from langdetect import detect


class GooglePipeline(object):
    def __init__(self):
        client = pymongo.MongoClient("localhost", 27017)
        SocialBird = client["PlatinumBusinessAnalytics"]
        self.ProjectData = SocialBird["ProjectData"]
        logging.log(logging.INFO, "Docuement Created Succeessfully!")

    def process_item(self, item, spider):
        if len(item["mention_text"]) < 3:
            return item

        temp_mention = item["mention_text"]
        temp_mention_list = temp_mention.split("[**break**]")
        temp_mention = " ".join(temp_mention_list)

        # b = TextBlob(temp_mention)
        # if b.detect_language() != 'en':
        #   return item
        if detect(temp_mention) != "en":
            return item

        r = requests.get(
            "http://127.0.0.1:5000/get_sentiment/", params={"text": temp_mention}
        )
        if r.status_code == 200:
            item["mention_sentiment"] = r.json()["Sentiment"]
        else:
            item["mention_sentiment"] = 2

        # item['review_sentiment'] = 1
        logging.warning("This is sentiment " + str(item["mention_sentiment"]))
        # self.temp_doc.insert_one(dict(item))
        self.ProjectData.update(
            {"_id": item["user_id"], "projects._id": item["project_id"]},
            {
                "$push": {
                    "projects.$.data": {
                        "site_url": item["site_url"],
                        "site_title": item["site_title"],
                        "mention_id": ObjectId(),
                        "publish_date": item["publish_date"],
                        "mention_text": item["mention_text"],
                        "mention_category": item["mention_category"],
                        "seen": False,
                        "mention_sentiment": item["mention_sentiment"],
                    }
                }
            },
        )
        return item
