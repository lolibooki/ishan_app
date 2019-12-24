from run import mongo
from bson.objectid import ObjectId
import datetime


def create_user(new_user):
    mongo.db.users.insert_one(new_user)


def find_user(key):
    return mongo.db.users.find_one(key)


def live_classes():
    lives = [item for item in mongo.db.lives.find()]  # return list of live classes
    for it in lives:
        it["_id"] = str(it["_id"])
    return lives


def ip_courses():
    ips = [item for item in mongo.db.ip.find()]  # return list of in person courses
    for it in ips:
        it["_id"] = str(it["_id"])
    return ips


def get_user_ip_course(course_id):
    return mongo.db.ip.find_one({'_id': ObjectId(course_id)})


def add_user_ip_course(user_id, course_id):
    temp = find_user({"_id": ObjectId(user_id)})['ipcourse']
    temp.append(ObjectId(course_id))
    mongo.db.users.update({"_id": ObjectId(user_id)}, {'$set':{'ipcourse': temp}})


def rec_courses():
    recs = [item for item in mongo.db.rec.find()]  # return list of recorded courses
    for it in recs:
        it["_id"] = str(it["_id"])
    return recs


def get_user_rec_course(course_id):
    return mongo.db.rec.find_one({'_id': ObjectId(course_id)})


def add_user_rec_course(user_id, course_id):
    temp = find_user({"_id": ObjectId(user_id)})['reccourse']
    temp[ObjectId(course_id)] = dict()
    mongo.db.users.update({"_id": ObjectId(user_id)}, {'$set': {'reccourse': temp}})


def live_courses():
    lives = [item for item in mongo.db.livc.find()]  # return list of live courses
    for it in lives:
        it["_id"] = str(it["_id"])
    return lives


def get_user_live_course(course_id):
    return mongo.db.livc.find_one({'_id': ObjectId(course_id)})


def add_user_live_course(user_id, course_id):
    temp = find_user({"_id": ObjectId(user_id)})['livecourse']
    temp[ObjectId(course_id)] = dict()
    mongo.db.users.update({"_id": ObjectId(user_id)}, {'$set': {'livecourse': temp}})


def submit_pay(buyer, course, ref_id, method):  # TODO: check if payment is in db
    payment = {'buyer': buyer,
               'course': course,
               'refid': ref_id,
               'method': method,
               'date': datetime.datetime.now()}
    try:
        mongo.db.pay.insert_one(payment)
        return True
    except:
        return False


class RevokedToken:
    def __init__(self, jti):
        self.query = {'jti': jti}
    
    def add(self):
        mongo.db.bjti.insert_one(self.query)
    
    @staticmethod
    def is_jti_blacklisted(jti):
        query = mongo.db.bjti.find_one(jti)
        if query:
            return True
        return False
