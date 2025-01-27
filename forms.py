from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, SelectField, IntegerField, FileField, TelField, EmailField, TextAreaField
from wtforms.validators import DataRequired, Email, EqualTo, Length, NumberRange, Optional  
from models.user import GenderEnum
from flask_wtf.file import FileAllowed
from utils import *
from flask_login import current_user  # Import current_user


class LoginForm(FlaskForm):
    email_or_username = StringField('Email or Username', 
                                validators=[DataRequired()],
                                render_kw={"placeholder": "Email or Username", "class": "single-field"})
    
    password = PasswordField('Password', 
                             validators=[DataRequired()],
                             render_kw={"placeholder": "Password", "class": "single-field"})
    
    remember_me = BooleanField('Remember me',
                           render_kw={"class": "checky-sec", "id": "c1"})
    
    submit = SubmitField('Login', render_kw={"class": "submit-btn"})


class RegisterForm(FlaskForm):
    email_createaccount = StringField('Email', 
                                      validators=[DataRequired(), Email()],
                                      render_kw={"placeholder": "Email", "class": "single-field"})
    
    username_createaccount = StringField('Username', 
                            validators=[DataRequired()],
                            render_kw={"placeholder": "Username", "class": "single-field"})
    
    firstname = StringField('First Name', 
                            validators=[DataRequired()],
                            render_kw={"placeholder": "First Name", "class": "single-field"})
    
    lastname = StringField('Last Name', 
                           validators=[DataRequired()],
                           render_kw={"placeholder": "Last Name", "class": "single-field"})
    
    gender = SelectField(
        'Gender', 
        choices=[('', 'Select Gender')] + GenderEnum.choices(), 
        validators=[DataRequired()],
        render_kw={"class": "nice-select"}
    )
    
    # gender = SelectField('Gender',
    #                      choices=[('', 'Select Gender')] + [(gender.name, gender.value) for gender in GenderEnum],
    #                      validators=[DataRequired()],
    #                      render_kw={"class": "nice-select"})
    
    age = IntegerField('Age', 
                       validators=[DataRequired(), NumberRange(min=16, max=66)],
                       render_kw={"class": "nice-select"})
    
    # country = SelectField('Country', 
    #                       choices=[('', 'Select Country')] + get_country_choices(), 
    #                       validators=[DataRequired()],
    #                       render_kw={"class": "nice-select"})
    country = SelectField(
        'Country',
        choices=[('', 'Select Country')] + get_country_choices(),
        validators=[DataRequired()],
        render_kw={"class": "nice-select"}
    )
    
    submit_createaccount = SubmitField('Create Account', 
                                       render_kw={"class": "submit-btn"})
    
class ResetPasswordForm(FlaskForm):
    email = EmailField('Email', 
                        validators=[DataRequired(), Email()],
                        render_kw={"placeholder": "Enter your email", "class": "single-field"})

    submit = SubmitField('Reset Password', render_kw={"class": "submit-btn"})    

class AccountForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    email = EmailField('Email', validators=[DataRequired(), Email()], render_kw={"disabled": True})  # Disabled field
    phone = TelField('Phone Number', validators=[Optional()])  # Make phone optional
    profile_pic = FileField(
        'Profile Picture',
        validators=[Optional(), FileAllowed(['jpg', 'jpeg', 'png', 'gif'], 'Only image files are allowed!')]
    )
    cover_pic = FileField(
        'Cover Picture',
        validators=[Optional(), FileAllowed(['jpg', 'jpeg', 'png', 'gif'], 'Only image files are allowed!')]
    )
    user_age = IntegerField('Age', validators=[DataRequired(), NumberRange(min=16, max=66)])
    gender = SelectField(
        'Gender', 
        choices=[('', 'Select Gender')] + GenderEnum.choices(), 
        validators=[DataRequired()],
        render_kw={"class": "nice-select"}
    )
    country = SelectField('Country', choices=[('', 'Select Country')] + get_country_choices(), validators=[DataRequired()])

class PasswordForm(FlaskForm):
    old_password = PasswordField("Old Password")
    new_password = PasswordField('New Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Repeat Password', validators=[
        DataRequired(),
        EqualTo('new_password', message="Passwords must match")
    ])
    submit = SubmitField('Save Setting')

class DeactivateAccountForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    explanation = TextAreaField('Please Explain Further', validators=[DataRequired()])
    email_option_out = BooleanField('Email option out')
    submit = SubmitField('Deactivate Account')