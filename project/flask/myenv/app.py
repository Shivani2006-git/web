from flask import Flask, render_template,url_for,redirect
from markupsafe import escape
from flask_sqlalchemy import SQLAlchemy
import mysql.connector
import bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField,PasswordField,SubmitField,validators
from flask_login import UserMixin,login_user,LoginManager,login_required,logout_user,current_user
from wtforms.validators import InputRequired,Length,ValidationError
from flask_bcrypt import Bcrypt




app=Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI']='mysql+pymysql://root1:Pass%40123@localhost/infor'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=False

app.config["SECRET_KEY"]= "thisisscreat"
db=SQLAlchemy(app)
bcrypt=Bcrypt(app)
login_manager=LoginManager()
login_manager.init_app(app)
login_manager.login_view="login"


@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))


class User(db.Model,UserMixin):
    __tablename__='user'
    id=db.Column(db.Integer,primary_key=True)
    usename=db.Column(db.String(120),unique=True,nullable=False)
    password=db.Column(db.String(200),nullable=False)
 
class RegisterForm(FlaskForm):
    usename=StringField(validators=[InputRequired(),Length(min=4,max=20)],render_kw={"placeholder":"username"})
    password=PasswordField(validators=[InputRequired(),Length(min=4,max=20)],render_kw={"placeholder":"passwoed"})
    submit=SubmitField("Register")
    def validate_usename(seelf,usename):
        existing_user_usename=User.query.filter_by(usename=usename.data).first()

        if existing_user_usename:
            raise ValidationError("the user name are exist pleasw enter differrent name")


class LoginForm(FlaskForm):
    usename=StringField(validators=[InputRequired(),Length(min=4,max=20)],render_kw={"placeholder":"username"})
    password=PasswordField(validators=[InputRequired(),Length(min=4,max=20)],render_kw={"placeholder":"passwoed"})

    submit=SubmitField("Login")



@app.route('/')
def about():
    return render_template("index.html")

@app.route('/login',methods=['GET','POST'])
def login():
    form=LoginForm()
    if form.validate_on_submit():
        user=User.query.filter_by(usename=form.usename.data).first()
        if user:
            if bcrypt.check_password_hash(user.password,form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
    return render_template("login.html",form=form)

@app.route('/register',methods=['GET','POST'])
def register():
    form=RegisterForm()
    if form.validate_on_submit():

        hashed_password= bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = User(usename=form.usename.data,password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template("register.html",form=form)

@app.route('/dashboard',methods=['GET','POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/logout',methods=['GET','POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

with app.app_context():
    db.create_all()
    print("table crreated sucressfully")



if  __name__=="__main__":
    
    app.run(debug=True)