# from flask import Flask, render_template, request, redirect, url_for, session
# from flask_mysqldb import MySQL
# import MySQLdb.cursors
# import re

# app = Flask(__name__)


# app.secret_key = 'xyzsdfg'

# app.config['MYSQL_HOST'] = 'host'
# app.config['MYSQL_USER'] = 'user'
# app.config['MYSQL_PASSWORD'] = 'password'
# app.config['MYSQL_DB'] = 'name_db'

# mysql = MySQL(app)


# @app.route('/')
# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     mesage = ''
#     if request.method == 'POST' and 'email' in request.form and 'password' in request.form:
#         email = request.form['email']
#         password = request.form['password']
#         cur = mysql.connection.cursor()
#         cur.execute("SELECT * FROM tasks")
#         data = cur.fetchall()
#         cur.close()
#         cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
#         cursor.execute(
#             'SELECT * FROM user WHERE email = % s AND password = % s', (email, password, ))
#         user = cursor.fetchone()
#         if user:
#             session['loggedin'] = True
#             session['userid'] = user['userid']
#             session['name'] = user['name']
#             session['email'] = user['email']
#             mesage = 'Logged in successfully !'
#             return render_template('user.html', mesage=mesage, tasks=data)
#         else:
#             mesage = 'Please enter correct email / password !'
#     return render_template('login.html', mesage=mesage)


# @app.route('/logout')
# def logout():
#     session.pop('loggedin', None)
#     session.pop('userid', None)
#     session.pop('email', None)
#     return redirect(url_for('login'))


# @app.route('/register', methods=['GET', 'POST'])
# def register():
#     mesage = ''
#     if request.method == 'POST' and 'name' in request.form and 'password' in request.form and 'email' in request.form:
#         userName = request.form['name']
#         password = request.form['password']
#         email = request.form['email']
#         cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
#         cursor.execute('SELECT * FROM user WHERE email = % s', (email, ))
#         account = cursor.fetchone()
#         if account:
#             mesage = 'Account already exists !'
#         elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
#             mesage = 'Invalid email address !'
#         elif not userName or not password or not email:
#             mesage = 'Please fill out the form !'
#         else:
#             cursor.execute(
#                 "INSERT INTO users (name, email, password) VALUES (%s, %s, %s)", (name, email, password))
#             mysql.connection.commit()
#             mesage = 'You have successfully registered !'
#     elif request.method == 'POST':
#         mesage = 'Please fill out the form !'
#     return render_template('register.html', mesage=mesage)


# @app.route('/add_task', methods=['POST'])
# def add_task():
#     if session['loggedin']:
#         if request.method == 'POST':
#             title = request.form['title']
#             date = request.form['date']
#             priority = request.form['priority']
#             cur = mysql.connection.cursor()
#             cur.execute("INSERT INTO tasks (title, date, priority, user_id) VALUES (%s, %s, %s, %s)",
#                         (title, date, priority, session['userid']))
#             mysql.connection.commit()
#             cur.close()
#             mesage = 'Task added successfully !'
#             return render_template('user.html', mesage=mesage)
#     else:
#         return redirect(url_for('login'))


# @app.route('/delete_task/<int:task_id>')
# def delete_task(task_id):
#     if session['loggedin']:
#         cur = mysql.connection.cursor()
#         cur.execute("DELETE FROM tasks WHERE id = %s AND user_id=%s",
#                     (task_id, session['userid']))
#         mysql.connection.commit()
#         cur.close()
#         mesage = 'Usunięto !'
#         return render_template('user.html', mesage=mesage)
#     else:
#         return redirect(url_for('login'))


# if __name__ == "__main__":
#     app.run()

from flask import *
from flask_mysqldb import MySQL
import re
import bcrypt
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from wtforms import Form, StringField, PasswordField, validators, DateField, SelectField
from flask_wtf import FlaskForm

app = Flask(__name__)
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'

# configure database
app.config['MYSQL_HOST'] = 'mysql-kborzy.alwaysdata.net'
app.config['MYSQL_USER'] = 'kborzy'
app.config['MYSQL_PASSWORD'] = 'Myflaskapp'
app.config['MYSQL_DB'] = 'kborzy_db'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
mysql = MySQL(app)

# configure login manager
login_manager = LoginManager()
login_manager.init_app(app)

# define user model


class User:
    def __init__(self, userid, name, email, password):
        self.userid = userid
        self.name = name
        self.email = email
        self.password = password

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return self.userid

# define login form


class LoginForm(Form):
    email = StringField(
        'Email', [validators.DataRequired(), validators.Email()])
    password = PasswordField('Password', [validators.DataRequired()])

# define registration form


class RegisterForm(Form):
    name = StringField('Name', [validators.DataRequired()])
    email = StringField(
        'Email', [validators.DataRequired(), validators.Email()])
    password = PasswordField(
        'Password', [validators.DataRequired(), validators.Length(min=6)])

# define task form


class TaskForm(FlaskForm):
    title = StringField('Title', validators=[validators.DataRequired()])
    date = DateField('Date', validators=[validators.DataRequired()])
    priority = SelectField('Priority', choices=[(
        'low', 'Low'), ('medium', 'Medium'), ('high', 'High')])

# load user from the database


@login_manager.user_loader
def load_user(userid):
    cur = mysql.connection.cursor()
    cur.execute(
        "SELECT userid, name, email, password FROM user WHERE userid = %s", (userid,))
    user = cur.fetchone()
    if user:
        return User(user['userid'], user['name'], user['email'], user['password'])
    return None

# login route


@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm(request.form)
    if request.method == 'POST' and form.validate():
        email = form.email.data
        password = form.password.data
        cur = mysql.connection.cursor()
        cur.execute(
            "SELECT userid, name, email, password FROM user WHERE email = %s", (email,))
        user = cur.fetchone()
        if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            login_user(User(user['userid'], user['name'],
                       user['email'], user['password']))
            flash('You have been log in!', "info")
            return redirect(url_for('tasks'))
        else:
            session['message'] = 'Invalid email or password'
            flash('Invalid email or password')
    return render_template('login.html', form=form)

# logout route


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You have been logged out", "info")
    return redirect(url_for('login'))

# register route


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data
        password = bcrypt.hashpw(
            form.password.data.encode('utf-8'), bcrypt.gensalt())
        cur = mysql.connection.cursor()
        cur.execute(
            "INSERT INTO user (name, email, password) VALUES (%s, %s, %s)", (name, email, password))
        mysql.connection.commit()
        cur.close()
        flash('You have successfully registered')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

# tasks route


@app.route('/tasks', methods=['GET', 'POST'])
@login_required
def tasks():
    form = TaskForm(request.form)
    if request.method == 'POST' and form.validate():
        title = form.title.data
        date = form.date.data
        priority = form.priority.data
        try:
            cur = mysql.connection.cursor()
            cur.execute("INSERT INTO tasks (title, date, priority, user_id) VALUES (%s, %s, %s, %s)",
                        (title, date, priority, current_user.get_id()))
            mysql.connection.commit()
            flash('Task added successfully', "info")
        except Exception as e:
            app.logger.error(e)
            session['message'] = 'Failed to add task'
        finally:
            cur.close()
    try:
        cur = mysql.connection.cursor()
        cur.execute(
            "SELECT id,title, date, priority,completed FROM tasks WHERE user_id = %s", (current_user.get_id(),))
        tasks = cur.fetchall()
    except Exception as e:
        app.logger.error(e)
        session['message'] = 'Failed to retrieve tasks'
    finally:
        cur.close()

    return render_template('tasks.html', form=form, tasks=tasks)


@app.route('/delete_task', methods=['POST'])
@login_required
def delete_task():
    task_id = request.form['task_id']
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM tasks WHERE id = %s", (task_id,))
    mysql.connection.commit()
    cur.close()
    flash('Task deleted successfully!')
    return redirect(url_for('tasks'))


@app.route('/update_task_status', methods=['POST'])
def update_task_status():
    task_id = request.form['task_id']
    task_status = request.form.get('status')
    if task_status is None:
        task_status = 0
    else:
        task_status = 1
    cur = mysql.connection.cursor()
    cur.execute("UPDATE tasks SET completed = %s WHERE id = %s",
                (task_status, task_id))
    mysql.connection.commit()
    cur.close()
    flash('Task status updated successfully!')
    return redirect(url_for('tasks'))


@app.route('/edit_task/<int:task_id>', methods=['GET', 'POST'])
def edit_task(task_id):
    cur = mysql.connection.cursor()
    cur.execute(
        "SELECT title, date, priority FROM tasks WHERE id = {}".format(task_id))
    task = cur.fetchone()

    form = TaskForm(request.form)
    form.title.data = task['title']
    form.date.data = task['date']
    form.priority.data = task['priority']
    if request.method == 'POST':
        title = request.form['title']
        date = request.form['date']
        priority = request.form['priority']
        cur = mysql.connection.cursor()
        cur.execute("""
            UPDATE tasks
            SET title=%s, date=%s, priority=%s
            WHERE id=%s
        """, (title, date, priority, task_id))
        mysql.connection.commit()
        flash('Task updated successfully')
        return redirect(url_for('tasks'))
    return render_template('edit_task.html', form=form, task=task)


if __name__ == '__main__':
    app.run(debug=True)
