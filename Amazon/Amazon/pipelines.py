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


class AmazonPipeline(object):
    def __init__(self):
        client = pymongo.MongoClient("localhost", 27017)
        SocialBird = client["PlatinumBusinessAnalytics"]
        self.ProjectData = SocialBird["ProjectData"]
        logging.log(logging.INFO, "Docuement Created Succeessfully!")

    def process_item(self, item, spider):
        # b = TextBlob(item['review_data'])
        # if b.detect_language() != 'en':
        #    return item
        if detect(item["review_data"]) != "en":
            return item

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
                        "review_title": item["review_title"],
                        "review_date": item["review_date"],
                        "review_data": item["review_data"],
                        "seen": False,
                        "review_sentiment": item["review_sentiment"],
                    }
                }
            },
        )
        logging.warning("Added amazon review to database...")
        return item

        """
        #I think match only works for first condition only or works for base attribute conditions and not for the nested ones...
        self.ProjectData.aggregate([
        {"$match": {
            "user_email": "shary12@gmail.com",
            "projects.project_name": "Adidas kaptur",
            "projects.data.user_name": {"$in": ["Angel Roldan"]},
        }},

        {"$unwind": "$projects"},
        {"$unwind": "$projects.data"},

        {"$match": {
            "projects.project_name": "Adidas kaptur",
            "projects.data.user_name": {"$in": ["Angel Roldan"]},
        }},

        {"$group": {
            "_id": {"user_email": "$user_email", "project_name": "$projects.project_name"},
            "data": {"$push": "$projects.data"}
        }},

        {"$group": {
            "_id": "$_id.user_email",
            "projects": {"$push": {
                "project_name": "$_id.project_name",
                "data": "$data"
            }}
        }}
        ])

        self.ProjectData.aggregate([
            {"$match": {
                "user_email": "shary12@gmail.com",
                "projects.project_name": "Adidas kaptur",
                "projects.data.review_date": {'$lt': datetime(2020, 1, 24), "$gte": datetime(2019, 11, 18) },
            }},

            {"$unwind": "$projects"},
            {"$unwind": "$projects.data"},

            {"$match": {
                "projects.project_name": "Adidas kaptur",
                "projects.data.review_date": {'$lt': datetime(2020, 1, 24), "$gte": datetime(2019, 11, 18) },
            }},

            {"$group": {
                "_id": {"user_email": "$user_email", "project_name": "$projects.project_name"},
                "data": {"$push": "$projects.data"}
            }},

            {"$group": {
                "_id": "$_id.user_email",
                "projects": {"$push": {
                    "project_name": "$_id.project_name",
                    "data": "$data"
                }}
            }}
        ])
        
        
        self.ProjectData.aggregate([
            {"$match": {
                "user_email": "shary12@gmail.com",
                "projects.project_name": "Adidas kaptur",
                "projects.data.review_date": {'$lt': datetime(2020, 1, 24), "$gte": datetime(2019, 11, 18) },
            }},

            {"$unwind": "$projects"},
            {"$unwind": "$projects.data"},

            {"$match": {
                "projects.project_name": "Adidas kaptur",
                "projects.data.review_date": {'$lt': datetime(2020, 1, 24), "$gte": datetime(2019, 11, 18) },
            }},
             {"$limit": 2},
             #So limit works after match, before grouping...

            {"$group": {
                "_id": {"user_email": "$user_email", "project_name": "$projects.project_name"},
                "data": {"$push": "$projects.data"}
            }},

            {"$group": {
                "_id": "$_id.user_email",
                "projects": {"$push": {
                    "project_name": "$_id.project_name",
                    "data": "$data"
                }}
            }}
        ])
        
        self.ProjectData.aggregate([
            {"$match": {
                "user_email": "shary12@gmail.com",
                "projects.project_name": "Adidas kaptur",
                "projects.data.review_date": {'$lt': datetime(2020, 1, 24), "$gte": datetime(2019, 11, 18) },
            }},

            {"$unwind": "$projects"},
            {"$unwind": "$projects.data"},

            {"$match": {
                "projects.project_name": "Adidas kaptur",
                "projects.data.review_date": {'$lt': datetime(2020, 1, 24), "$gte": datetime(2019, 11, 18) },
            }},
             {"$limit": 20},
             {"$sort": {"projects.data.review_date": -1}},
             #So limit works after match, before grouping...

            {"$group": {
                "_id": {"user_email": "$user_email", "project_name": "$projects.project_name"},
                "data": {"$push": "$projects.data"}
            }},

            {"$group": {
                "_id": "$_id.user_email",
                "projects": {"$push": {
                    "project_name": "$_id.project_name",
                    "data": "$data"
                }}
            }}
        ])
        
        
        self.ProjectData.aggregate([
            {"$match": {
                "user_email": "shary12@gmail.com",
                "projects.project_name": "Adidas kaptur",
                "projects.data.review_date": {'$lt': datetime(2020, 1, 24), "$gte": datetime(2019, 11, 18) },
            }},

            {"$unwind": "$projects"},
            {"$unwind": "$projects.data"},

            {"$match": {
                "projects.project_name": "Adidas kaptur",
                "projects.data.review_date": {'$lt': datetime(2020, 1, 24), "$gte": datetime(2019, 11, 18) },
            }},
             {"$sort": {"projects.data.review_date": -1}},
             #So limit works after match, before grouping...

            {"$group": {
                "_id": {"user_email": "$user_email", "project_name": "$projects.project_name"},
                "data": {"$push": "$projects.data"}
            }},

            {"$group": {
                "_id": "$_id.user_email",
                "projects": {"$push": {
                    "project_name": "$_id.project_name",
                    "data": "$data"
                }}
            }}
        ])
        
        self.ProjectData.aggregate([
            {"$match": {
                "user_email": "shary12@gmail.com",
                "projects.project_name": "Adidas kaptur",
                "projects.data.review_date": {'$lt': datetime(2020, 1, 24), "$gte": datetime(2019, 11, 18) },
            }},

            {"$unwind": "$projects"},
            {"$unwind": "$projects.data"},

            {"$match": {
                "projects.project_name": "Adidas kaptur",
                "projects.data.review_date": {'$lt': datetime(2020, 1, 24), "$gte": datetime(2019, 11, 18) },
            }},
             {"$sort": {"projects.data.review_date": -1}},
             #So limit works after match, before grouping...
             
             {"$match": {
                "projects.data.review_date": {"$gte": datetime(2020, 1, 15) },
            }},

            {"$group": {
                "_id": {"user_email": "$user_email", "project_name": "$projects.project_name"},
                "data": {"$push": "$projects.data"}
            }},

            {"$group": {
                "_id": "$_id.user_email",
                "projects": {"$push": {
                    "project_name": "$_id.project_name",
                    "data": "$data"
                }}
            }}
        ])
        
        
        
        
        
        
        
        
        
        """
