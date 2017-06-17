#!/usr/bin/python
import pymongo
connection = pymongo.MongoClient("localhost", 27017)
db = connection.AAA
collection  = db.testCollection
collection.insert({"number":0})
