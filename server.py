from flask import Flask,render_template,redirect,request,session,flash
import re
from flask_bcrypt import Bcrypt
from mysqlconnection import connectToMySQL   

app = Flask(__name__)
bcrypt = Bcrypt(app)

app.secret_key = "validation"
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')


@app.route('/')
def index():
        return render_template("index.html")

@app.route('/register', methods=['POST', 'GET'])
def register():
        if request.form:
            is_valid = True
            if len(request.form['first_name']) < 3:
                is_valid = False
                flash("First name must be at least 2 characters!")
                return redirect('/')
            if len(request.form['last_name']) < 3:
                is_valid = False
                flash("Last name must be at least 2 characters!")
                return redirect('/')
            if not EMAIL_REGEX.match(request.form['email']):
                is_valid = False    # test whether a field matches the pattern
                flash("Invalid email address!")
                return redirect('/')
            if len(request.form['password']) < 8:
                is_valid = False
                flash("Password must be at least 8 characters")
                return redirect('/')
            if request.form['password'] != request.form['confirm_password']:
                is_valid = False
                flash("Passwords do not match!")
                return redirect('/')
            else:
                pw_hash = bcrypt.generate_password_hash(request.form['password'])
                query = "INSERT INTO users (first_name, last_name, email, password) VALUES (%(first_name)s, %(last_name)s, %(email)s, %(password_hash)s);"
                data = {
                    "first_name":request.form['first_name'],
                    "last_name":request.form['last_name'],
                    "email":request.form['email'],
                    "password_hash":pw_hash
                }
                user_id = connectToMySQL('private-wall').query_db(query, data)
                if user_id is False:
                    flash("This email is already a registered user!")
                    return redirect('/')
                session['user_id'] = user_id
                return redirect(f"/wall/{user_id}")
        else:
            return redirect("/")

@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.form:
        is_valid = True
        if not EMAIL_REGEX.match(request.form['email']):
            flash("Invalid email address!")
            return redirect('/')
        else:
            query = "SELECT * FROM users WHERE email = %(email)s;"
            data = {
                "email":request.form['email']
            }
            users = connectToMySQL('private-wall').query_db(query, data)
            if len(users) != 1:
                is_valid=False
                flash("Email not registered")
                return redirect('/')  
            if not bcrypt.check_password_hash(users[0]['password'], request.form['password']):
                is_valid=False
                flash("Incorrect Password")
                return redirect('/')  
            session['user_id'] = users[0]['id']
            user_id = users[0]['id']
            return redirect(f"/wall/{user_id}")
    else:
        return render_template("index.html")

@app.route('/wall/<int:user_id>', methods=['GET'])
def wall(user_id):
        if "user_id" not in session:
            flash("User not logged in!")
            return redirect('/')
        if session.get("user_id") != user_id:
            session.clear()
            flash("Action Forbidden")
            flash("User has been logged out")
            return redirect('/')
        query = "SELECT users.first_name, messages.user_id, messages.message, messages.recipient_id FROM messages LEFT JOIN users ON users.id = messages.user_id WHERE messages.recipient_id = %(user_id)s;"
        data = {
            "user_id":user_id
        }
        messages = connectToMySQL('private-wall').query_db(query, data)
        print(messages)

        allusers = "SELECT * FROM users WHERE users.id <> %(user_id)s;"
        all_users = connectToMySQL('private-wall').query_db(allusers, data)

        individual = "SELECT * FROM users WHERE id = %(user_id)s;"
        users = connectToMySQL('private-wall').query_db(individual, data)

        messagessent = "SELECT COUNT(messages.user_id) AS sent FROM messages WHERE messages.user_id = %(user_id)s;" 
        messages_sent = connectToMySQL('private-wall').query_db(messagessent, data)[0]['sent']

        messagesreceived = "SELECT COUNT(messages.user_id) AS received FROM messages WHERE messages.recipient_id = %(user_id)s;" 
        messages_received = connectToMySQL('private-wall').query_db(messagesreceived, data)[0]['received']

        return render_template("wall.html", messages=messages, users=users, all_users=all_users, messages_sent=messages_sent, messages_received=messages_received)

@app.route('/send_message/<int:user_id>', methods=['POST', 'GET'])
def send_message(user_id):
    query = "INSERT INTO messages (user_id, recipient_id, message) VALUES (%(user_id)s, %(recipient_id)s, %(message)s);"
    data = {
        "user_id":user_id,
        "recipient_id":request.form['recipient_id'],
        "message":request.form['message']
    }
    messages = connectToMySQL('private-wall').query_db(query, data)
    return redirect(f'/wall/{user_id}')

@app.route('/delete_message/<int:user_id>/<int:recipient_id>', methods=['POST'])
def delete_message(user_id, recipient_id):
    if session.get("user_id") != recipient_id:
        return redirect('/')
    query = "DELETE FROM messages WHERE user_id = %(user_id)s AND recipient_id = %(recipient_id)s;"
    data = {
        "user_id":user_id,
        "recipient_id":recipient_id
    }
    print(query)
    messages = connectToMySQL('private-wall').query_db(query, data)
    return redirect(f'/wall/{recipient_id}')

@app.route('/logout', methods=['POST'])
def logout():
        session.clear()
        return redirect('/')
        
if __name__ == "__main__":
    app.run(debug=True)