from flask import Flask, render_template,request
from markupsafe import escape
from flask_sqlalchemy import SQLAlchemy
import mysql.connector
import bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField,PasswordField,SubmitField,validators
import secrets
import os
from flask_login import (LoginManager,UserMixin,login_user,login_required,current_user)
app= Flask(__name__)
mydb=mysql.connector.connect(
    host="localhost",
    username="root2",
    password="Pass@1234",
    database="mydb"
)
app.config["SECRET_KEY"]= os.urandom(64)
mycursor=mydb.cursor()
mycursor.execute("create table if not exists login(id int primary key auto_increment ,email VARCHAR(255),password VARCHAR(255),name VARCHAR(100) )")


print("done")
login_manager=LoginManager(app)
@login_manager.user_loader
def load_user(id):
    return user.query.get(id)


    

@app.route('/',methods=['GET'])
def test():
    try:
        print(request.args)
        myname=request.args.get('name')
        myage=request.args.get('age')
    
        print(myname)
       
        return render_template("index.html")
    except Exception as e:
        return"provide valid da"
        raise
@app.route('/about')
def about():
    return render_template("about.html")
@app.route('/dept')    
@app.route('/dept/<name>')
def dept(name=None):
    return render_template("department.html",vara=name)
    

@app.route('/form',methods=['GET','POST'])
def form():
   

    
    if request.method =='POST':
        name=request.form['name']
        email=request.form['email']
        password=request.form['password']

        hashed_password=bcrypt.hashpw(password.encode('utf-8'),bcrypt.gensalt())
        mycursor.execute(" insert into login(name,email,password)values(%s,%s,%s)",(name,email,hashed_password))
    
        mydb.commit()
        return "sucess"
    return render_template("form.html")

@app.route("/user",methods=['GET'])
def user():
    mycursor=mydb.cursor()
    mycursor.execute("select * from user")
    data=mycursor.fetchall()
    return render_template("user.html",students=data)

@app.route('/update/<int:user_id>',methods=['POST','GET'])
def update(user_id):
    
    mycursor.execute("select id from login where id=%s",(user_id))
    user=cursor.fe
    if request.method =='POST':
        name=request.form['name']
        email=request.form['email']
        age=request.form['age']

        user.name=name
        user.email=email
        user.age=age

        return f"user {name}uapdated sucessfully"
    return render_template("update.hatml")

class Signin(FlaskForm):
    email =StringField("Enter email",[validators.DataRequired()])
    password =PasswordField("Enter paaword",[validators.DataRequired()])
    submit =SubmitField("login")
    
@app.route('/signin',methods=['GET','POST'])
def signin():
    form=Signin()
    if form.validate_on_submit():
        email=form.email.data
        password=form.password.data
        mycursor.execute("select * from login where email=%s limit 1",(email))
        user=mycursor.fetchone()
        if user and bcrypt.checkpw(password.encode('utf-8'),user.password.encode('utf-8')):
            login_user(user)
            return redirect(url_for("protected"))


    return render_template('signin.html',form=form)

    @app.rount('/protected')
    @login_required
    def protected():
        return render_template('home.html',user=current_user)


        
        
        
    



@app.route('/image')
def image():
    return render_template("image.html")



if  __name__=="__main__":
    
    app.run(debug=True)