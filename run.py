from flask import Flask, jsonify, request, render_template
from flask_restful import Api
# from flask_sqlalchemy import SQLAlchemy
from flask_pymongo import PyMongo
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from bson.objectid import ObjectId
from suds.client import Client
import datetime
from flask_admin import Admin
import dbforms

MMERCHANT_ID = 'aca6038e-06a7-11e9-bcad-005056a205be'
ZARINPAL_WEBSERVICE = 'https://zarinpal.com/pg/services/WebGate/wsdl'

app = Flask(__name__)
api = Api(app)

app.config["MONGO_URI"] = "mongodb://localhost:27017/students"
app.config['SECRET_KEY'] = 'feb7a837-6c72-4ec2-ac2d-7225ee89b1be'
app.config['JWT_SECRET_KEY'] = '95279529-a66a-4312-a240-2312264db599'
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']

jwt = JWTManager(app)
mongo = PyMongo(app)
CORS(app)


@jwt.expired_token_loader
def my_expired_token_callback(expired_token):
    token_type = expired_token['type']
    return jsonify({
        'status': 403,
        'message': 'The {} token has expired'.format(token_type)
    }), 403


@app.route('/')
def index():
    return render_template('index.html')
    # return jsonify({'message': 'Hello, World!'})


@jwt.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
    jti = decrypted_token['jti']
    return models.RevokedToken.is_jti_blacklisted({"jti": jti})


# TODO: add redirecting to application
@app.route('/PayCallback/<int:method>/<string:user>/<string:course>/<int:price>/<string:ctype>',
           methods=['GET', 'POST'])
def verify(method, user, course, price, ctype):
    client = Client(ZARINPAL_WEBSERVICE)
    if request.args.get('Status') == 'OK':
        result = client.service.PaymentVerification(MMERCHANT_ID,
                                                    request.args['Authority'],
                                                    price)
        if result.Status == 100:
            if models.submit_pay(user, course, result.RefID, method):
                if ctype == 'ip':
                    models.add_user_ip_course(user, course)
                elif ctype == 'rec':
                    models.add_user_rec_course(user, course)
                elif ctype == 'liv':
                    models.add_user_live_course(user, course)
                else:
                    return {'status': 400,
                            'message': 'پرداخت شما انجام شد ولی در فرآیند ثبت کلاس مشکلی پیش آمده.'
                                       'لطفا با پشتیبانی تماس بگیرید.'
                                       'شماره مرجع پرداخت شما:',
                            'refID': str(result.RefID)}
                return {'status': 200,
                        'refID': str(result.RefID)}
            else:
                return {'status': 404,
                        'message': 'not found'}
        elif result.Status == 101:
            return 'Transaction submitted : ' + str(result.Status)
        else:
            return {'status': 403,
                    'message': 'Transaction failed',
                    'refID': str(result.Status)}
    else:
        return {'status': 404,
                'message': 'Transaction failed or canceled by user'}

import models, resources

api.add_resource(resources.UserRegistration, '/registration')
api.add_resource(resources.UserLogin, '/login')
api.add_resource(resources.UserLogoutAccess, '/logout/access')
api.add_resource(resources.UserLogoutRefresh, '/logout/refresh')
api.add_resource(resources.TokenRefresh, '/token/refresh')
api.add_resource(resources.GetLiveClasses, '/liveClass')
api.add_resource(resources.GetRecordedCourses, '/recCourse')
api.add_resource(resources.GetLiveCourses, '/liveCourse')
api.add_resource(resources.GetInPersonCourses, '/inpersonCourse')
api.add_resource(resources.GetUserIPCourses, '/userIPCourse')
api.add_resource(resources.GetUserLiveCourses, '/userLiveCourse')
api.add_resource(resources.GetUserRecCourses, '/userRecCourse')
api.add_resource(resources.GetPayUrl, '/pay/getUrl')
api.add_resource(resources.SendMessage, '/mail/send')
api.add_resource(resources.GetMessages, '/mail/get')
api.add_resource(resources.CourseDetail, '/getCourseDetail')
api.add_resource(resources.EditUser, '/editUser')
api.add_resource(resources.Test, '/test')


if __name__ == "__main__":
    admin = Admin(app)
    admin.add_view(dbforms.UserView(mongo.db.users, 'User'))
    app.run(debug=True)
