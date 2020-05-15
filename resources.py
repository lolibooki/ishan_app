from flask_restful import Resource, reqparse
from passlib.hash import pbkdf2_sha256 as sha256
from flask_jwt_extended import (create_access_token,
                                create_refresh_token,
                                jwt_required,
                                jwt_optional,
                                jwt_refresh_token_required,
                                get_jwt_identity,
                                get_raw_jwt)
# from userschema import validate_user
# from bson.json_util import dumps
from suds.client import Client
import werkzeug, os
import models
import datetime
from bson import ObjectId
import ast
import logging

# TODO: make settings file instead of below!
MMERCHANT_ID = 'aca6038e-06a7-11e9-bcad-005056a205be'
ZARINPAL_WEBSERVICE = 'https://zarinpal.com/pg/services/WebGate/wsdl'
PAYMENT_DESCRIPTION = 'بابت خرید دوره {}'
MOBILE = '09190734256'
EMAIL = 'salamat@salamat.ir'
SERVER_IP = 'http://136.243.32.187'
UPLOAD_FOLDER = "static/uploads"
COURSE_REQUESTS = "static/requests"
ACCESS_TOKEN_EXPIRE = datetime.timedelta(minutes=30)  # access token expiration time
parser = reqparse.RequestParser()
# parser.add_argument('fname', help = 'This field cannot be blank', required = True)
# parser.add_argument('password', help = 'This field cannot be blank', required = True)

logging.basicConfig(format='%s(asctime)s - %(message)s',
                    level=logging.DEBUG,
                    filename='logs/app.log')


class UserRegistration(Resource):
    def post(self):

        parser_copy = parser.copy()
        # required
        parser_copy.add_argument('fname', help='This field cannot be blank', required=True)
        parser_copy.add_argument('lname', help='This field cannot be blank', required=True)
        parser_copy.add_argument('mphone', help='This field cannot be blank', required=True)
        parser_copy.add_argument('email', help='This field cannot be blank', required=True)
        parser_copy.add_argument('mcode', help='This field cannot be blank', required=True)
        parser_copy.add_argument('pass', help='This field cannot be blank', required=True)
        # not required
        parser_copy.add_argument('phone', required=False)
        parser_copy.add_argument('state', required=False)
        parser_copy.add_argument('city', required=False)
        parser_copy.add_argument('address', required=False)

        data = parser_copy.parse_args()

        # check if user is new or not
        if models.find_user({"mphone": data['mphone']}):
            logging.warning('request for registering user that exists. user: {}'.format(data['mphone']))
            return {'status': 400,
                    'message': 'User {} already exists'. format(data['mphone'])}

        new_user = {
            "fname": data['fname'],
            "lname": data['lname'],
            "mphone": data['mphone'],
            "phone": data['phone'],
            "email": data['email'],
            "mcode": data['mcode'],
            "state": data['state'],
            "city": data['city'],
            "address": data['address'],
            "pass": sha256.hash(data['pass']),
        }

        try:
            models.create_user(new_user)
            access_token = create_access_token(identity=data['mphone'],
                                               expires_delta=ACCESS_TOKEN_EXPIRE)
            refresh_token = create_refresh_token(identity=data['mphone'])
            logging.info('user created. user: {}'.format(data['mphone']))
            return {
                'status': 200,
                'message': 'User {} {} was created'.format(data['fname'], data['lname']),
                'access_token': access_token,
                'refresh_token': refresh_token
            }
        except Exception as e:
            logging.error('exception occurred', exc_info=True)
            return {'status': 500,
                    'message': 'Something went wrong'}


class EditUser(Resource):
    @jwt_required
    def post(self):
        parser_copy = parser.copy()
        # optional
        parser_copy.add_argument('fname', required=False)
        parser_copy.add_argument('lname', required=False)
        # parser_copy.add_argument('mphone', required=False)
        parser_copy.add_argument('email', required=False)
        parser_copy.add_argument('mcode', required=False)
        # parser_copy.add_argument('pass', required=False)
        parser_copy.add_argument('phone', required=False)
        parser_copy.add_argument('state', required=False)
        parser_copy.add_argument('city', required=False)
        parser_copy.add_argument('address', required=False)

        data = parser_copy.parse_args()

        current_user = models.find_user({"mphone": get_jwt_identity()})

        updated_user = dict()
        for item in data:
            if not data[item]:
                continue
            else:
                updated_user[item] = data[item]

        if models.update_user({"_id": current_user["_id"]}, updated_user):
            return {'status': 200,
                    'message': 'successfully updated'}
        else:
            return {'status': 500,
                    'message': 'internal error'}


# TODO: error handling the incorrect user name
class UserLogin(Resource):
    def post(self):
        parser_copy = parser.copy()
        parser_copy.add_argument('mphone', help='This field cannot be blank', required=True)
        parser_copy.add_argument('pass', help='This field cannot be blank', required=True)
        data = parser_copy.parse_args()

        if not models.find_user({"mphone": data['mphone']}):
            return {'status': 400,
                    'message': 'User {} doesn\'t exist'.format(data['mphone'])}

        current_user = models.find_user({"mphone": data['mphone']})
        if sha256.verify(data['pass'], current_user['pass']):
            access_token = create_access_token(identity=data['mphone'], expires_delta=ACCESS_TOKEN_EXPIRE)
            refresh_token = create_refresh_token(identity=data['mphone'])
            current_user["_id"] = str(current_user['_id'])
            logging.info('user logged in. user: {}'.format(data['mphone']))
            return {
                'status': 200,
                'message': 'Logged in as {}'.format(current_user['mphone']),
                'access_token': access_token,
                'refresh_token': refresh_token,
                'user_data': {key: current_user.get(key, None) for key in ['fname',
                                                                           'lname',
                                                                           'mphone',
                                                                           'phone',
                                                                           'email',
                                                                           'mcode',
                                                                           'state',
                                                                           'city',
                                                                           'address']}
            }
        else:
            logging.warning('unsuccessful login attempt. ip: {}'.format(reqparse.request.headers.getlist("X-Real-IP")))
            return {'status': 400,
                    'message': 'Wrong credentials'}


class UserLogoutAccess(Resource):
    @jwt_required
    def post(self):
        jti = get_raw_jwt()['jti']
        try:
            revoked_token = models.RevokedToken(jti)
            revoked_token.add()
            return {'status': 200,
                    'message': 'Access token has been revoked'}
        except Exception as e:
            logging.error('exception occurred', exc_info=True)
            return {'status': 500,
                    'message': 'Something went wrong'}


class UserLogoutRefresh(Resource):
    @jwt_refresh_token_required
    def post(self):
        jti = get_raw_jwt()['jti']
        try:
            revoked_token = models.RevokedToken(jti)
            revoked_token.add()
            return {'status': 200,
                    'message': 'Access token has been revoked'}
        except Exception as e:
            logging.error('exception occurred', exc_info=True)
            return {'status': 500,
                    'message': 'Something went wrong'}


class TokenRefresh(Resource):
    @jwt_refresh_token_required
    def post(self):
        current_user = get_jwt_identity()
        access_token = create_access_token(identity=current_user, expires_delta=ACCESS_TOKEN_EXPIRE)
        logging.info('request for refreshing token. user: {} ip: {}'.format(current_user,
                                                                            reqparse.request.headers.getlist(
                                                                                "X-Real-IP")))
        return {'status': 200,
                'access_token': access_token}


class GetLiveClasses(Resource):
    def get(self):
        logging.info('get live class request. ip: {}'.format(reqparse.request.headers.getlist("X-Real-IP")))
        return models.live_classes()


class GetRecordedCourses(Resource):
    def get(self):
        logging.info('get recorded courses request. ip: {}'.format(reqparse.request.headers.getlist("X-Real-IP")))
        return models.rec_courses()


class GetLiveCourses(Resource):
    def get(self):
        logging.info('get live courses request. ip: {}'.format(reqparse.request.headers.getlist("X-Real-IP")))
        return models.live_courses()


class GetInPersonCourses(Resource):
    def get(self):
        logging.info('get in person courses request. ip: {}'.format(reqparse.request.headers.getlist("X-Real-IP")))
        return models.ip_courses()


class Test(Resource):
    @jwt_required
    def post(self):
        current_user = get_jwt_identity()
        logging.info('TEST check. ip: {}'.format(reqparse.request.headers.getlist("X-Real-IP")))
        return current_user


# TODO: check for user payment installments
class GetUserIPCourses(Resource):
    @jwt_required
    def post(self):
        current_user = get_jwt_identity()
        user = models.find_user({"mphone": current_user})
        courses = list()
        for item in user['ipcourse']:
            current_course = models.get_user_ip_course(item)
            current_course['_id'] = str(current_course['_id'])
            courses.append(current_course)
        return courses


class GetUserLiveCourses(Resource):  # TODO: checking users absences
    @jwt_required
    def post(self):
        current_user = get_jwt_identity()
        user = models.find_user({"mphone": current_user})
        live_course_ids = list(user['livecourse'].keys())
        courses = list()
        for item in live_course_ids:
            current_course = models.get_user_live_course(item)
            current_course['_id'] = str(current_course['_id'])
            courses.append(current_course)
        return courses


# checking for course weeks and does not allow that future weeks include in response json
class GetUserRecCourses(Resource):
    @jwt_required
    def post(self):
        current_user = get_jwt_identity()
        user = models.find_user({'mphone': current_user})
        rec_course_ids = [ObjectId(_id) for _id in user['reccourse'].keys()]
        current_date = datetime.datetime.now()
        current_time = datetime.date(current_date.year, current_date.month, current_date.day).isocalendar()
        courses = list()
        for item in rec_course_ids:
            current_course = models.get_user_rec_course(item)
            current_course['_id'] = str(current_course['_id'])
            course_time = datetime.date(current_course['s_time'].year,
                                        current_course['s_time'].month,
                                        current_course['s_time'].day).isocalendar()
            if current_time[0] == course_time[0]:
                week_delta = current_time[1] - course_time[1]
            else:
                week_delta = current_time[1] + 52 - course_time[1]
            if current_time[1] == course_time[1] and current_time[2] >= course_time[2]:
                week_delta += 1
            null_maker = False  # use for nullify weeks after not passed quiz
            for week in current_course['weeks']:
                if null_maker is True or int(week) > week_delta:
                    current_course['weeks'][week] = None

                if current_course['weeks'][week] is not None:
                    if current_course['weeks'][week].get("quiz") is None:
                        null_maker = False
                    else:
                        if user["reccourse"][str(item)]["exams"].get(current_course['weeks'][week]["quiz"]) is None:
                            null_maker = True
                        else:
                            _last = user["reccourse"][str(item)]["exams"][current_course['weeks'][week]["quiz"]][-1]
                            if _last.get("passed") is None:
                                null_maker = True
                            elif _last["passed"] is False:
                                null_maker = True

            current_course['s_time'] = current_course['s_time'].isoformat()
            courses.append(current_course)
        return courses


class GetPayUrl(Resource):
    @jwt_required
    def post(self):
        parser_copy = parser.copy()
        parser_copy.add_argument('_id', help='This field cannot be blank', required=True)
        parser_copy.add_argument('ctype', help='This field cannot be blank', required=True)  # ip/rec/liv
        parser_copy.add_argument('method', help='This field cannot be blank', required=True)  # 1:full/3:installment
        data = parser_copy.parse_args()

        current_user = get_jwt_identity()
        user = models.find_user({'mphone': current_user})

        if data['ctype'] == "ip":
            if ObjectId(data["_id"]) in user["ipcourse"]:
                return {'status': 405,
                        'message': 'this course is currently purchased'}
            courses = models.ip_courses(_id=data['_id'])
        elif data['ctype'] == "rec":
            if ObjectId(data["_id"]) in user["reccourse"].keys():
                return {'status': 405,
                        'message': 'this course is currently purchased'}
            courses = models.rec_courses(_id=data['_id'])
        elif data['ctype'] == "liv":
            if ObjectId(data["_id"]) in user["reccourse"].keys():
                return {'status': 405,
                        'message': 'this course is currently purchased'}
            courses = models.live_courses(_id=data['_id'])
        else:
            return {'status': 400,
                    'message': 'course type or id is incorrect'}
        try:
            # TODO: in db all prices must be in integer form not price with "," sign!
            course_price = int(int(courses['price'].replace(',', ''))/int(data['method']))
            payment_desc = PAYMENT_DESCRIPTION.format(courses['title'])
            # for item in courses:
            #     if item["_id"] == ObjectId(data['_id']):
            #         course_price = int(item['price'])/int(data['method'])
            #         payment_desc = PAYMENT_DESCRIPTION.format(item['title'])
            if not course_price or not payment_desc:
                return {'status': 500,
                        'message': 'course does not exist'}
        except KeyError as e:
            return {'status': 404,
                    'message': e}

        callback_url = SERVER_IP + '/PayCallback/{}/{}/{}/{}/{}'.format(data['method'],
                                                                        str(user['_id']),
                                                                        data['_id'],
                                                                        course_price,
                                                                        data['ctype'])

        client = Client(ZARINPAL_WEBSERVICE)
        result = client.service.PaymentRequest(MMERCHANT_ID,
                                               course_price,
                                               payment_desc,
                                               EMAIL,
                                               MOBILE,
                                               callback_url)
        # for debug
        print(result, course_price, callback_url, payment_desc)
        if result.Status == 100:
            return {'status': 200,
                    'url': 'https://www.zarinpal.com/pg/StartPay/' + result.Authority}
        else:
            return {'status': 500,
                    'error': 'Zarinpal is not responding'}


class SendMessage(Resource):  # TODO: add exercise field to db
    @jwt_required
    def post(self):
        parser_copy = parser.copy()
        parser_copy.add_argument('file', type=werkzeug.datastructures.FileStorage, location='files')

        parser_copy.add_argument('to', help='This field cannot be blank', required=True)
        parser_copy.add_argument('title', help='This field cannot be blank', required=True)
        parser_copy.add_argument('body', help='This field cannot be blank', required=True)
        # id of replied message
        parser_copy.add_argument('reply', required=False)
        # boolean to check if its a exercise or not
        parser_copy.add_argument('exc', required=False)

        data = parser_copy.parse_args()

        current_user = get_jwt_identity()
        user = models.find_user({'mphone': current_user})

        message = {
            'title': data['title'],
            'body': data['body'],
            'sender': user['_id'],
            'receiver': data['to'],
            'reply': data['reply'],
            'exc': data['exc'],
            'active': True,
            'date': datetime.datetime.now()
        }

        if not data['file']:
            if data['exc']:
                return {'status': 400,
                        'message': 'exercise file not included'}
            models.send_message(message)
            return {'status': 200,
                    'message': 'email sent'}

        file = data['file']
        if file:
            # file name format is: "date-user_id-filename" like: "201985-5db425890dfc269af386f9f0-file.zip"
            file_name = '{}-{}-{}'.format(str(datetime.datetime.now().date()).replace('-', ''),
                                          user['_id'],
                                          file.filename)
            file.save(os.path.join(UPLOAD_FOLDER, file_name))
            message['attach'] = os.path.join(UPLOAD_FOLDER, file_name)
            message_id = models.send_message(message)
            if data['exc']:
                models.user_rec_exc_update(
                    user['_id'], data['receiver'], message_id)
            return {'status': 200,
                    'message': 'email sent'}
        return {'status': 500,
                'message': 'something went wrong!'}


# TODO: deactivating mails base on click
class GetMessages(Resource):
    @jwt_optional
    def post(self):
        parser_copy = parser.copy()
        parser_copy.add_argument('method', help='This field cannot be blank', required=True)  # sent or get
        # boolean: if request for admin or not
        parser_copy.add_argument('admin', required=False)

        data = parser_copy.parse_args()

        current_user = get_jwt_identity()
        if current_user:
            user = models.find_user({'mphone': current_user})
            messages = models.get_message(data['method'], user['_id'])
        else:
            if data['admin']:
                messages = models.get_message(data['method'], 'admin')
            else:
                return {'status': 400,
                        'message': 'if not login, admin field must be include'}
        json_message = list()
        for item in messages:
            item['_id'] = str(item['_id'])
            item['sender'] = str(item['sender'])
            item['receiver'] = str(item['receiver'])
            item['date'] = item['date'].isoformat()
            if item['reply']:
                item['reply'] = str(item['reply'])
            json_message.append(item)
        return json_message


class CourseDetail(Resource):
    def post(self):
        parser_copy = parser.copy()
        parser_copy.add_argument('_id', help='This field cannot be blank', required=True)

        data = parser_copy.parse_args()

        try:
            if models.rec_courses(_id=data['_id']):
                return models.rec_courses(_id=data['_id'])
            elif models.ip_courses(_id=data['_id']):
                return models.ip_courses(_id=data['_id'])
            elif models.live_courses(_id=data['_id']):
                return models.live_courses(_id=data['_id'])
            else:
                return {'status': 400,
                        'message': 'id is incorrect'}
        except Exception as e:
            return {'status': 400,
                    'message': 'id not included'}


class Fields(Resource):
    def post(self):
        parser_copy = parser.copy()
        parser_copy.add_argument('_id', required=False)
        parser_copy.add_argument('field_name', required=False)

        try:
            data = parser_copy.parse_args()
            _id = data.get('_id', None)
        except:
            _id = None

        try:
            data = parser_copy.parse_args()
            field_name = data.get('field_name', None)
        except:
            field_name = None

        if field_name is not None:
            fields = models.fields(name=field_name)
        else:
            fields = models.fields(_id=_id)

        for item in fields:
            duration = 0
            for _item in item['clist']:
                # course_duration = 0
                if _item['course'] is not None:
                    if isinstance(_item['course'], list):
                        subdur = 0
                        course_list = list()
                        for course in _item['course']:
                            dur = len(models.rec_courses(_id=course)['weeks'])
                            course_list.append(models.rec_courses(_id=course))
                            if dur > subdur:
                                subdur = dur
                        course_duration = subdur
                        _item['course'] = course_list
                    else:
                        course_duration = len(models.rec_courses(_id=_item['course'])['weeks'])
                        _item['course'] = models.rec_courses(_id=_item['course'])
                    duration += course_duration
            item['duration'] = duration

        logging.info('get fields request. ip: {}'.format(reqparse.request.headers.getlist("X-Real-IP")))
        return fields


class Teacher(Resource):
    def post(self):
        parser_copy = parser.copy()
        parser_copy.add_argument('_id', required=False)

        try:
            data = parser_copy.parse_args()
            _id = data.get('_id', None)
        except:
            _id = None

        return models.get_teachers(_id=_id)


class Articles(Resource):
    def post(self):
        parser_copy = parser.copy()
        parser_copy.add_argument('_id', required=False)

        try:
            data = parser_copy.parse_args()
            _id = data.get('_id', None)
        except:
            _id = None
        
        return models.get_articles(_id=_id)
    

class Comments(Resource):
    def post(self):
        parser_copy = parser.copy()
        parser_copy.add_argument('_id', required=False)

        try:
            data = parser_copy.parse_args()
            _id = data.get('_id', None)
        except:
            _id = None
        
        return models.get_comments(_id=_id)
    

class PreOrder(Resource):
    def post(self):
        parser_copy = parser.copy()
        
        parser_copy.add_argument('file', type=werkzeug.datastructures.FileStorage, location='files')
        parser_copy.add_argument('fname', help='This field cannot be blank', required=True)
        parser_copy.add_argument('lname', help='This field cannot be blank', required=True)
        parser_copy.add_argument('mphone', help='This field cannot be blank', required=True)
        parser_copy.add_argument('phone', help='This field cannot be blank', required=True)
        parser_copy.add_argument('gender', help='This field cannot be blank', required=True)
        parser_copy.add_argument('city', help='This field cannot be blank', required=True)
        parser_copy.add_argument('address', help='This field cannot be blank', required=True)
        parser_copy.add_argument('softskill', help='This field cannot be blank', required=False)
        parser_copy.add_argument('otherskill', help='This field cannot be blank', required=False)
        parser_copy.add_argument('course', help='This field cannot be blank', required=True)
        parser_copy.add_argument('adv_time', help='This field cannot be blank', required=True)

        data = parser_copy.parse_args()

        try:
            course = models.rec_courses(_id=data['course'])
        except:
            return {'status': 400,
                    'message': 'invalid course id'}

        field = models.fields(name=course['field_name'])

        if data['file'] is None:
            for item in field['clist']:
                if course["_id"] in item['course']:
                    if int(item['term']) > 1:
                        return {'status': 400,
                                'message': 'course has prerequisite, must include project file'}

        order = {
            'fname': data['fname'],
            'lname': data['lname'],
            'mphone': data['mphone'],
            'adv_time': datetime.datetime.strptime(data['adv_time'], "%Y-%m-%dT%H:%M:%S"),
            'phone': data['phone'],
            'gender': data['gender'],
            'city': data['city'],
            'address': data['address'],
            'softskill': data.get('softskill', None),
            'otherskill': data.get('otherskill', None),
            'course': data['course'],
            'status': 0
        }

        file = data['file']
        if file:
            # file name format is: "date-username-filename" like: "201985-AhmadTroy-file.zip"
            file_name = '{}-{}-{}'.format(str(datetime.datetime.now().date()).replace('-', ''),
                                          data['fname']+data['lname'],
                                          file.filename)
            file.save(os.path.join(COURSE_REQUESTS, file_name))
            order['attach'] = os.path.join(UPLOAD_FOLDER, file_name)

        sub = models.pre_order(order)
        if not sub:
            return {'status': 500,
                    'message': 'something went wrong'}
        else:
            return {'status': 200,
                    'message': 'pre order submitted'}


class GetUserStatus(Resource):
    @jwt_required
    def post(self):
        parser_copy = parser.copy()
        parser_copy.add_argument('_id', help='This field cannot be blank', required=True)

        data = parser_copy.parse_args()

        current_user = get_jwt_identity()
        user = models.find_user({'mphone': current_user})

        if data['_id'] in user['reccourse'].keys():
            return user['reccourse'][data['_id']]['status']['lastSeen']
        else:
            return {'status': 400,
                    'message': 'course id is invalid'}


class SetUserStatus(Resource):
    @jwt_required
    def post(self):
        parser_copy = parser.copy()
        parser_copy.add_argument('_id', help='This field cannot be blank', required=True)
        parser_copy.add_argument('week', help='This field cannot be blank', required=True)
        parser_copy.add_argument('part', help='This field cannot be blank', required=True)

        data = parser_copy.parse_args()

        current_user = get_jwt_identity()
        user = models.find_user({'mphone': current_user})

        logging.info('set status. user: {} week: {} part: {}'.format(user["mphone"], data["week"], data["part"]))

        if data['_id'] not in user['reccourse'].keys():
            return {'status': 400,
                    'message': 'course id is invalid'}

        try:
            last_seen = user['reccourse'][data['_id']]['status']['lastSeen']
        except:
            user['reccourse'][data['_id']] = {'status': {'lastSeen': {'week': 0, 'part': 0}}}
            last_seen = user['reccourse'][data['_id']]['status']['lastSeen']

        if int(data['week']) < int(last_seen['week']):
            return {'status': 401,
                    'message': 'user is ahead'}
        else:
            if int(data['part']) < int(last_seen['part']):
                return {'status': 401,
                        'message': 'user id ahead'}

        user['reccourse'][data['_id']]['status']['lastSeen'] = {'week': data['week'],
                                                                'part': data['part']}

        models.update_user({"_id": user["_id"]}, {'reccourse': user['reccourse']})

        return {'status': 200,
                'message': 'status updated',
                'data': {
                    'week': data['week'],
                    'part': data['part']
                }}


class GetQuiz(Resource):
    @jwt_required
    def post(self):
        parser_copy = parser.copy()
        parser_copy.add_argument('course_id', help='This field cannot be blank', required=True)
        parser_copy.add_argument('quiz_id', help='This field cannot be blank', required=True)

        data = parser_copy.parse_args()

        current_user = get_jwt_identity()
        user = models.find_user({'mphone': current_user})

        quiz = models.get_quiz(data["quiz_id"])

        if user["reccourse"][data["course_id"]]["exams"].get(data["quiz_id"]) is None:
            user["reccourse"][data["course_id"]]["exams"][data["quiz_id"]] = [{"attempt": 1,
                                                                               "start": datetime.datetime.now()}]
        else:
            if user["reccourse"][data["course_id"]]["exams"][data["quiz_id"]][-1].get("end") is None:
                user["reccourse"][data["course_id"]]["exams"][data["quiz_id"]][-1]["end"] = "unfinished"
                models.update_user({"_id": user["_id"]}, {"reccourse": user["reccourse"]})
                return {'status': 403,
                        'message': 'last quiz was unfinished'}
            attempt_num = len(user["reccourse"][data["course_id"]]["exams"][data["quiz_id"]])
            if attempt_num < quiz["attemptLock"]:
                user["reccourse"][data["course_id"]]["exams"][data["quiz_id"]].append({"attempt": attempt_num+1,
                                                                                       "start": datetime.datetime.now()}
                                                                                      )
            else:
                return {'status': 401,
                        'message': 'no attempt left'}

        logging.info('user {} starts quiz.'.format(user['mphone']))
        models.update_user({"_id": user["_id"]}, {"reccourse": user["reccourse"]})
        return {"status": 200,
                "questions": quiz["questions"],
                "quiz_time": quiz["time"],
                "min_score": quiz["accept"],
                "negative_points": quiz["negPoint"],
                "attempts_remaining": quiz["attemptLock"] -
                                      len(user["reccourse"][data["course_id"]]["exams"][data["quiz_id"]])}


class SubmitQuiz(Resource):
    @jwt_required
    def post(self):
        time = datetime.datetime.now()

        parser_copy = parser.copy()
        parser_copy.add_argument('course_id', help='This field cannot be blank', required=True)
        parser_copy.add_argument('quiz_id', help='This field cannot be blank', required=True)
        parser_copy.add_argument('answers', help='This field cannot be blank', required=True)

        data = parser_copy.parse_args()

        current_user = get_jwt_identity()
        user = models.find_user({'mphone': current_user})

        logging.info('user {} submits quiz.'.format(user['mphone']))

        quiz = models.get_quiz(data["quiz_id"])

        if user["reccourse"][data["course_id"]]["exams"][data["quiz_id"]][-1].get("end") is not None:
            return {'status': 404,
                    'message': 'first start the quiz'}
        else:
            user["reccourse"][data["course_id"]]["exams"][data["quiz_id"]][-1]["end"] = time

        if (time - user["reccourse"][data["course_id"]]["exams"][data["quiz_id"]][-1]["start"]).seconds > quiz["time"]:
            user["reccourse"][data["course_id"]]["exams"][data["quiz_id"]][-1]["score"] = 0
            user["reccourse"][data["course_id"]]["exams"][data["quiz_id"]][-1]["passed"] = False
            models.update_user({"_id": user["_id"]}, {"reccourse": user["reccourse"]})
            return {"status": 403,
                    "messsage": "time passed"}

        score = self.quiz_correction(ast.literal_eval(data["answers"]), quiz["answers"], quiz["points"])
        if isinstance(score, list):
            return {"status": 400,
                    "message": score}

        user_answers = ast.literal_eval(data["answers"])
        user_answers["user"] = user["_id"]
        user_answers["exam"] = quiz["_id"]
        user_answers["course"] = ObjectId(data["course_id"])
        models.submit_exam(user_answers)

        user["reccourse"][data["course_id"]]["exams"][data["quiz_id"]][-1]["score"] = score

        if score >= quiz["accept"]:
            user["reccourse"][data["course_id"]]["exams"][data["quiz_id"]][-1]["passed"] = True

            # HARD CODED **********************************************
            user["reccourse"][data["course_id"]]["status"] = {
                "lastSeen": {
                    "week": "2",
                    "part": "1"
                }
            }
            # HARD CODED **********************************************

            models.update_user({"_id": user["_id"]}, {"reccourse": user["reccourse"]})
            return {"status": 200,
                    "score": score}
        else:
            user["reccourse"][data["course_id"]]["exams"][data["quiz_id"]][-1]["passed"] = False
            models.update_user({"_id": user["_id"]}, {"reccourse": user["reccourse"]})
            return {"status": 201,
                    "score": score}

    def quiz_correction(self, user_answers, correct_answers, points):
        final_point = 0
        errors = list()

        if len(user_answers) < len(correct_answers):
            errors.append("answer count does not match")
            return errors

        for item in correct_answers:
            if correct_answers[item]["type"] == "test":
                if correct_answers[item]["answer"] == user_answers[item]:
                    final_point += points[int(item)-1]
            elif correct_answers[item]["type"] == "blank":
                if correct_answers[item]["ordered"] is True:
                    corrects = 0
                    for i in range(len(correct_answers[item]["answer"])):
                        if correct_answers[item]['answer'][i] == user_answers[item][i]:
                            corrects += 1
                    final_point += points[int(item) - 1] / len(correct_answers[item]["answer"]) * corrects
                else:
                    corrects = 0
                    for answer in correct_answers[item]["answer"]:
                        if answer in user_answers[item]:
                            corrects += 1
                    final_point += points[int(item) - 1] / len(correct_answers[item]["answer"]) * corrects
            elif correct_answers[item]["type"] == "tf":
                corrects = 0
                for i in range(len(correct_answers[item]["answer"])):
                    if correct_answers[item]['answer'][i] == user_answers[item][i]:
                        corrects += 1
                final_point += points[int(item) - 1] / len(correct_answers[item]["answer"]) * corrects
            else:
                pass

        return final_point
