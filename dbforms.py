from wtforms import form, fields, validators
from flask_admin.contrib.pymongo import ModelView
import models


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
    reccourse = fields.StringField('reccourse')


class UserView(ModelView):
    column_list = ('fname', 'lname', 'mphone', 'phone', 'email', 'mcode', 'reccourse')
    column_sortable_list = ('lname', 'mphone')
    can_create = True
    can_edit = True

    form = UserForm

    def get_list(self, *args, **kwargs):
        count, data = super(UserView, self).get_list(*args, **kwargs)
        course_list = list()
        for item in data:
            if item.get('reccourse'):
                item['reccourse'] = [models.rec_courses(_id=course)['title'] for course in item["reccourse"].keys()]
        return count, data

    def _get_course_list(self, form):
        courses = [item['title'] for item in models.rec_courses()]
        form.reccourse.choices = courses
        return form

    def create_model(self, _form):
        _form = super(UserView, self).create_form()
        return self._get_course_list(_form)
