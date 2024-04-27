from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
from wtforms.validators import DataRequired, Email
from wtforms import StringField, PasswordField, SubmitField, SelectField


class CreatePasswordForm(FlaskForm):
    website_name = StringField('Website Name', validators=[DataRequired()])
    website_url = StringField('Website URL')
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    category = StringField('Category')
    submit = SubmitField('Add Password')


class EditPasswordForm(FlaskForm):
    website_name = StringField('Website Name', validators=[DataRequired()])
    website_url = StringField('Website URL')
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    category = StringField('Category')
    submit = SubmitField('Update Password')
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Update')


class CreateUserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    role = SelectField('Role', choices=[('admin', 'Admin'), ('standard', 'Standard')])
    submit = SubmitField('Create User')

