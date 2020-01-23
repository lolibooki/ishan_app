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
import logging

# TODO: make settings file instead of below!
MMERCHANT_ID = 'aca6038e-06a7-11e9-bcad-005056a205be'
ZARINPAL_WEBSERVICE = 'https://zarinpal.com/pg/services/WebGate/wsdl'
PAYMENT_DESCRIPTION = 'بابت خرید دوره {}'
MOBILE = '09190734256'
EMAIL = 'salamat@salamat.ir'
SERVER_IP = 'http://136.243.32.187'
UPLOAD_FOLDER = "static/uploads"
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

        if models.find_user({"mphone": data['mphone']}):  # check if user is new or not
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

        current_user = models.find_user({"mphone": data['mphone']})

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
            access_token = create_access_token(identity=data['mphone'],
                                               expires_delta=ACCESS_TOKEN_EXPIRE)
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
            logging.warning('unsuccessful login attempt. ip: {}'.format(reqparse.request.remote_addr))
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
        access_token = create_access_token(identity=current_user,
                                           expires_delta=ACCESS_TOKEN_EXPIRE)
        logging.info('request for refreshing token. user: {} ip: {}'.format(current_user, reqparse.request.remote_addr))
        return {'status': 200,
                'access_token': access_token}


class GetLiveClasses(Resource):
    def get(self):
        logging.info('get live class request. ip: {}'.format(reqparse.request.remote_addr))
        return models.live_classes()


class GetRecordedCourses(Resource):
    def get(self):
        logging.info('get recorded courses request. ip: {}'.format(reqparse.request.remote_addr))
        return models.rec_courses()


class GetLiveCourses(Resource):
    def get(self):
        logging.info('get live courses request. ip: {}'.format(reqparse.request.remote_addr))
        return models.live_courses()


class GetInPersonCourses(Resource):
    def get(self):
        logging.info('get in person courses request. ip: {}'.format(reqparse.request.remote_addr))
        return models.ip_courses()


class Test(Resource):
    @jwt_required
    def post(self):
        current_user = get_jwt_identity()
        logging.info('TEST check. ip: {}'.format(reqparse.request.remote_addr))
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
            for week in current_course['weeks']:
                if int(week) > week_delta:
                    current_course['weeks'][week] = None
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

        if data['ctype'] == "ip":
            courses = models.ip_courses(_id=data['_id'])
        elif data['ctype'] == "rec":
            courses = models.rec_courses(_id=data['_id'])
        elif data['ctype'] == "liv":
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

        current_user = get_jwt_identity()
        user = models.find_user({'mphone': current_user})

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
                    'error': 'Zarinpal not responding'}


class SendMessage(Resource):  # TODO: add exercise field to db
    @jwt_required
    def post(self):
        parser_copy = parser.copy()
        parser_copy.add_argument('file', type=werkzeug.datastructures.FileStorage, location='files')

        parser_copy.add_argument('to', help='This field cannot be blank', required=True)
        parser_copy.add_argument('title', help='This field cannot be blank', required=True)
        parser_copy.add_argument('body', help='This field cannot be blank', required=True)
        parser_copy.add_argument('reply', required=False)  # id of replied message
        parser_copy.add_argument('exc', required=False)  # boolean to check if its a exercise or not

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
                models.user_rec_exc_update(user['_id'], data['receiver'], message_id)
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
        parser_copy.add_argument('admin', required=False)  # boolean: if request for admin or not

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
            if models.ip_courses(_id=data['_id']):
                return models.ip_courses(_id=data['_id'])
            elif models.live_courses(_id=data['_id']):
                return models.live_courses(_id=data['_id'])
            else:
                return {'status': 400,
                        'message': 'id is incorrect'}
        except Exception as e:
            return {'status': 400,
                    'message': 'id not included'}
