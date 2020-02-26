from wtforms import form, fields, validators, widgets
from flask_admin.contrib.pymongo import ModelView
from passlib.hash import pbkdf2_sha256 as sha256


class UserForm(form.Form):
    fname = fields.StringField("fname")
    lname = fields.StringField("lname")
    mphone = fields.StringField("mphone")
    phone = fields.StringField("phone")
    email = fields.StringField("email", [validators.Length(min=3, max=120), validators.Email()])
    mcode = fields.StringField("mcode")
    state = fields.StringField("state")
    city = fields.StringField("city")
    address = fields.StringField("address")
    password = fields.PasswordField("pass")
    reccourse = fields.SelectField('reccourse', widget=widgets.Select())


class UserView(ModelView):
    column_list = ('fname', 'lname', 'mphone', 'phone', 'email', 'mcode', 'reccourse')
    column_sortable_list = ('lname', 'mphone')
    can_create = True
    can_edit = True

    form = UserForm

    def get_list(self, *args, **kwargs):
        import models
        count, data = super(UserView, self).get_list(*args, **kwargs)
        print('get_list')
        course_list = list()
        for item in data:
            if item.get('reccourse'):
                item['reccourse'] = [models.rec_courses(_id=course)['title'] for course in item["reccourse"].keys()]
        return count, data

    def _get_course_list(self, _form):
        import models
        print('_get_course_list')
        courses = [(item['_id'], item['title']) for item in models.rec_courses()]
        _form.reccourse.choices = courses
        return _form

    def create_form(self):
        print('create_form')
        _form = super(UserView, self).create_form()
        return self._get_course_list(_form)

    def edit_form(self, obj):
        print('edit_form')
        _form = super(UserView, self).edit_form(obj)
        return self._get_course_list(_form)

    def on_model_change(self, _form, model, is_created):
        password = model.get('password')
        model['password'] = sha256.hash(password)
        reccourse = model.get('reccourse')
        print(reccourse)
        return model
