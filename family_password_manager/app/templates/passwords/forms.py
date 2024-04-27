from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired

class CreatePasswordForm(FlaskForm):
    website_name = StringField('Website Name', validators=[DataRequired()])
    website_url = StringField('Website URL')
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    category = StringField('Category')
    submit = SubmitField('Add Password')
