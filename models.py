# TODO: all functions needs docstring
from run import mongo
from bson.objectid import ObjectId
import datetime


def create_user(new_user):
    mongo.db.users.insert_one(new_user)


def find_user(key):
    return mongo.db.users.find_one(key)


def update_user(user, data):
    if mongo.db.users.update(user, {"$set": data}):
        return True
    return False


def live_classes():
    lives = [item for item in mongo.db.lives.find()]  # return list of live classes
    for it in lives:
        it["_id"] = str(it["_id"])
        it['s_time'] = it['s_time'].isoformat()
    return lives


def ip_courses(_id=None):
    if _id:
        ip = mongo.db.ip.find_one({"_id": ObjectId(_id)})
        if ip:
            ip["_id"] = str(ip["_id"])
            ip['s_time'] = ip['s_time'].isoformat()
        return ip
    else:
        ips = [item for item in mongo.db.ip.find()]  # return list of in person courses
        for it in ips:
            it["_id"] = str(it["_id"])
            it['s_time'] = it['s_time'].isoformat()
        return ips


def get_user_ip_course(course_id):
    return mongo.db.ip.find_one({'_id': ObjectId(course_id)})


def add_user_ip_course(user_id, course_id):
    temp = find_user({"_id": ObjectId(user_id)})['ipcourse']
    temp.append(ObjectId(course_id))
    mongo.db.users.update({"_id": ObjectId(user_id)}, {'$set': {'ipcourse': temp}})


def rec_courses(_id=None):
    if _id:
        rec = mongo.db.rec.find_one({"_id": ObjectId(_id)})
        if rec:
            rec["_id"] = str(rec["_id"])
            rec['s_time'] = rec['s_time'].isoformat()
        return rec
    else:
        recs = [item for item in mongo.db.rec.find()]  # return list of recorded courses
        for it in recs:
            it["_id"] = str(it["_id"])
            it['s_time'] = it['s_time'].isoformat()
        return recs


def get_user_rec_course(course_id):
    return mongo.db.rec.find_one({'_id': ObjectId(course_id)})


def add_user_rec_course(user_id, course_id):
    temp = find_user({"_id": ObjectId(user_id)})['reccourse']
    temp[ObjectId(course_id)] = dict()
    mongo.db.users.update({"_id": ObjectId(user_id)}, {'$set': {'reccourse': temp}})


# TODO: bellow function needs a heavy debug!!
def user_rec_exc_update(user, course, message):
    """
    :param user: ObjectId
    :param course: String
    :param message: ObjectId
    :return: null
    """
    temp = find_user({"_id": user})['reccourse'][ObjectId(course)]  # returns list of exercises for course
    temp.append(message)
    mongo.db.users.update({"_id": user}, {'$set': {'reccourse': {ObjectId(course): temp}}})


def live_courses(_id=None):
    if _id:
        live = mongo.db.livc.find_one({"_id": ObjectId(_id)})
        if live:
            live["_id"] = str(live["_id"])
            live['s_time'] = live['s_time'].isoformat()
        return live
    else:
        lives = [item for item in mongo.db.livc.find()]  # return list of live courses
        for it in lives:
            it["_id"] = str(it["_id"])
            it['s_time'] = it['s_time'].isoformat()
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


def send_message(message):
    _id = mongo.db.messages.insert_one(message)
    return _id


def get_message(method, user):
    """
    :param method: str: sent/get
    :param user: ObjectId or str(admin)
    :return: list of messages
    """
    if method == "sent":
        return mongo.db.messages.find({"sender": user})
    elif method == "get":
        return mongo.db.messages.find({"receiver": user})


def fields(_id=None, name=None):
    if name:
        _fields = [fi for fi in mongo.db.fields.find({"name": name})]
    elif _id:
        _fields = [fi for fi in mongo.db.fields.find({'_id': ObjectId(_id)})]
    else:
        _fields = [fi for fi in mongo.db.fields.find()]
    for item in _fields:
        item["_id"] = str(item["_id"])
        for _item in item['clist']:
            if isinstance(_item['course'], list):
                courses = list()
                for course in _item['course']:
                    courses.append(str(course))
                _item['course'] = courses
            else:
                _item['course'] = str(_item['course'])
    return _fields


def get_teachers(_id=None):
    if _id:
        teacher = mongo.db.teachers.find_one({"_id": ObjectId(_id)})
        teacher["_id"] = str(teacher["_id"])
        return teacher
    teachers = [item for item in mongo.db.teachers.find()]
    for teach in teachers:
        teach["_id"] = str(teach["_id"])
    return teachers


def get_articles(_id=None):
    if _id:
        article = mongo.db.articles.find_one({"_id": ObjectId(_id)})
        article["_id"] = str(article["_id"])
        return article
    articles = [item for item in mongo.db.articles.find()]
    for art in articles:
        art["_id"] = str(art["_id"])
    return articles


def get_comments(_id=None):
    if _id:
        comment = mongo.db.comments.find_one({"_id": ObjectId(_id)})
        comment["_id"] = str(comment["_id"])
        return comment
    comments = [item for item in mongo.db.comments.find()]
    for comm in comments:
        comm["_id"] = str(comm["_id"])
    return comments


def pre_order(order):
    try:
        object_id = mongo.db.preorder.insert(order)
        return object_id
    except:
        return False


def get_quiz(_id):
    quiz = mongo.db.quiz.find_one({"_id": ObjectId(_id)})
    quiz["_id"] = str(quiz["_id"])
    return quiz


def submit_score(score):
    mongo.db.quiz.insert(score)


def submit_exam(exam):
    mongo.db.exam.insert(exam)


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
