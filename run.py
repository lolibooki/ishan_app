from flask import Flask, jsonify, request, render_template
from flask_restful import Api
from werkzeug.contrib.fixers import ProxyFix
# from flask_sqlalchemy import SQLAlchemy
from flask_pymongo import PyMongo
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from bson.objectid import ObjectId
from suds.client import Client
import datetime
from flask_admin import Admin
# import dbforms

from wtforms import form, fields, TextAreaField, widgets
from flask_admin.form.upload import FileUploadField
from flask_admin.contrib.pymongo import ModelView
from flask_admin.contrib.fileadmin import FileAdmin
import os.path as op

MMERCHANT_ID = 'aca6038e-06a7-11e9-bcad-005056a205be'
ZARINPAL_WEBSERVICE = 'https://zarinpal.com/pg/services/WebGate/wsdl'

app = Flask(__name__)
api = Api(app)

app.config["MONGO_URI"] = "mongodb://localhost:27017/students"
app.config['SECRET_KEY'] = 'some-secret-string'
app.config['JWT_SECRET_KEY'] = 'jwt-secret-string'
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
@app.route('/marks')
@app.route('/settings')
@app.route('/contact')
@app.route('/download')
@app.route('/logout')
@app.route('/mail/inbox')
@app.route('/mail/sent')
@app.route('/login')
@app.route('/course/<course>')
def index(course=None):
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
api.add_resource(resources.Fields, '/field')
api.add_resource(resources.Teacher, '/teacher')
api.add_resource(resources.Articles, '/articles')
api.add_resource(resources.Comments, '/comments')
api.add_resource(resources.PreOrder, '/preOrder')
api.add_resource(resources.Test, '/test')


class CKTextAreaWidget(widgets.TextArea):
    def __call__(self, field, **kwargs):
        if kwargs.get('class'):
            kwargs['class'] += ' ckeditor'
        else:
            kwargs.setdefault('class', 'ckeditor')
        return super(CKTextAreaWidget, self).__call__(field, **kwargs)


class CKTextAreaField(TextAreaField):
    widget = CKTextAreaWidget()


path = op.join(op.dirname(__file__), 'static')


class Article(form.Form):
    title = fields.StringField("title")
    img = FileUploadField(label="image", base_path=path)
    text = CKTextAreaField("text")
    tags = fields.StringField("tags")


class ArticleView(ModelView):
    extra_js = ['//cdn.ckeditor.com/4.6.0/standard/ckeditor.js']
    form_overrides = {
        'body': CKTextAreaField
    }
    
    column_list = ('title', 'img')
    column_sortable_list = ('title')
    can_create = True
    can_edit = True
    
    form = Article

    def on_model_change(self, _form, model, is_created):
        model['img'].save(op.join('static/articles', model['img'].filename))
        model['img'] = model['img'].filename
        model['tags'] = model['tags'].split('-')
        return model


class Comment(form.Form):
    title = fields.StringField("title")
    name = fields.StringField("name")
    profession = fields.StringField("prof")
    img = FileUploadField(label="image", base_path=path)
    text = CKTextAreaField("text")


class CommentView(ModelView):
    extra_js = ['//cdn.ckeditor.com/4.6.0/standard/ckeditor.js']
    form_overrides = {
        'body': CKTextAreaField
    }
    
    column_list = ('title', 'name', 'profession', 'img', 'text')
    column_sortable_list = 'title'
    can_create = True
    can_edit = True
    
    form = Comment
    
    def on_model_change(self, _form, model, is_created):
        model['img'].save(op.join('static/comments', model['img'].filename))
        model['img'] = model['img'].filename
        return model
    

admin = Admin(app, url='/ishanAdmin', template_mode='bootstrap3')
admin.add_view(FileAdmin(path, '/static/', name='Files'))
admin.add_view(ArticleView(mongo.db.articles, 'Articles'))
admin.add_view(CommentView(mongo.db.comments, 'Comments'))


if __name__ == "__main__":
    app.wsgi_app = ProxyFix(app.wsgi_app)
    # admin = Admin(app, url='/ishanAdmin')
    # admin.add_view(FileAdmin(path, '/static/', name='Files'))
    # admin.add_view(ArticleView(mongo.db.articles, 'Articles'))
    # admin.add_view(dbforms.UserView(mongo.db.users, 'User'))
    app.run(debug=True)
