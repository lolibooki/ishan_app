from wtforms import form, fields, validators
from flask_admin.contrib.pymongo import ModelView


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
    reccoures = fields.Field('reccourse')


class UserView(ModelView):
    column_list = ('fname', 'lname', 'mphone', 'phone', 'email', 'mcode', 'reccourse')
    column_sortable_list = ('lname', 'mphone')
    form = UserForm
