
import re
from Crypto.Protocol.KDF import PBKDF2

import bleach
from Crypto.Cipher import AES
from flask import Flask, render_template, request, make_response, redirect
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import markdown
from collections import deque
from datetime import datetime, timedelta
from passlib.hash import sha256_crypt
import sqlite3
from time import sleep
from flask_sslify import SSLify


app = Flask(__name__)
#sslify = SSLify(app)

@app.after_request
def after_request(response):
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["Server"] = 'Flask-Server'
    return response


login_manager = LoginManager()
login_manager.init_app(app)

app.secret_key = "206363ef77d567cc511df5098695d2b85058952afd5e2b1eecd5aed981805e60"

DATABASE = "./sqlite3.db"

key = ""


class User(UserMixin):
    pass


def encode(text, password):
    print("encoded", type(text), type(password))
    key = PBKDF2(password, b"salt")
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    enc_note = cipher.encrypt(text.encode()) + nonce
    return enc_note


def chceck_if_user_exist(username):
    db = sqlite3.connect(DATABASE)
    sql = db.cursor()
    result = sql.execute("SELECT username FROM User WHERE username = ?", [username])
    db.close()
    print('query result', result)
    if result == None:
        return False
    else:
        return True


def insert_new_user(username, hashed_password):
    db = sqlite3.connect(DATABASE)
    sql = db.cursor()
    sql.execute("INSERT INTO user (username, password) VALUES (?, ?)", (username, hashed_password))
    db.commit()
    db.close()


def checkpasswordrequirements(password):
    if len(password) < 16:
        return False
    if not re.search("[a-z]", password):
        return False
    if not re.search("[A-Z]", password):
        return False
    if not re.search("[0-9]", password):
        return False
    if not re.search("[@_!#$%^&*()<>?/\|}{~:]", password):
        return False
    return True


@login_manager.user_loader
def user_loader(username):
    if username is None:
        return None

    db = sqlite3.connect(DATABASE)
    sql = db.cursor()
    sql.execute(f"SELECT username, password FROM user WHERE username = '{username}'")
    row = sql.fetchone()
    try:
        username, password = row
    except:
        return None

    user = User()
    user.id = username
    user.password = password
    return user


@login_manager.request_loader
def request_loader(request):
    username = request.form.get('username')
    user = user_loader(username)
    return user


recent_users = deque(maxlen=3)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register_page.html")
    if request.method == "POST":
        sleep(1)
        username = bleach.clean(request.form.get("username"))
        password = bleach.clean(request.form.get("password"))
        password_retyped = bleach.clean(request.form.get("password_retyped"))
        sleep(3)
        if not checkpasswordrequirements(password):
            return "Hasło nie spełnia wymagań", 401

        if password == password_retyped:
            if chceck_if_user_exist(username):
                password_encrypted = sha256_crypt.hash(password)
                insert_new_user(username, password_encrypted)
                print('username', username)
                user = user_loader(username)
                print('user', user)
                login_user(user)
                return redirect('/hello')
            else:
                return "Taki użytkownik już istnieje", 401
        else:
            return "Hasła nie pokrywają sie", 401


attempts = {}


@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("index.html")
    if request.method == "POST":
        username = bleach.clean(request.form.get("username"))
        password = bleach.clean(request.form.get("password"))
        user = user_loader(username)
        sleep(2)
        if user is None:
            return "Nieprawidłowy login lub hasło", 401
        if password is None:
            return "Nieprawidłowy login lub hasło", 401

        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR')
        if client_ip in attempts:
            if attempts[client_ip]['attempts'] >= 3:
                if datetime.now() - attempts[client_ip]['last_attempt'] < timedelta(minutes=1):
                    return "Too many login attempts. Please try again later.", 401
                else:
                    attempts[client_ip]['attempts'] = 0
        else:
            attempts[client_ip] = {'attempts': 0, 'last_attempt': datetime.now()}

        if sha256_crypt.verify(password, user.password):
            login_user(user)
            attempts[client_ip]['attempts'] = 0
            return redirect('/hello')
        else:
            attempts[client_ip]['attempts'] += 1
            attempts[client_ip]['last_attempt'] = datetime.now()
            return "Nieprawidłowy login lub hasło", 401


@app.route("/logout")
def logout():
    logout_user()
    return redirect("/")


@app.route("/hello", methods=['GET'])
@login_required
def hello():
    if request.method == 'GET':
        print(current_user.id)
        username = current_user.id
        db = sqlite3.connect(DATABASE)
        sql = db.cursor()
        sql.execute(f"SELECT id FROM notes WHERE username == '{username}'")
        notes = sql.fetchall()
        sql.execute(f"SELECT id FROM notes WHERE is_public = 1")
        shared_notes = sql.fetchall()
        sql.execute(f"SELECT id FROM notes WHERE is_encrypted = 1 and username == '{username}'")
        encrypted_notes = sql.fetchall()
        db.close()
        return render_template("hello.html", username=username, notes=notes, shared_notes=shared_notes,
                               encrypted_notes=encrypted_notes)


@app.route("/render", methods=['POST'])
@login_required
def render():
    allowed_tags = ['p', 'b', 'i', 'u', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6' 'a', 'img', 'strong', 'em']
    allowed_atributes = {
        'a': ['href'],
        'img': ['src', 'width', 'height']
    }
    md = bleach.clean(request.form.get("markdown", ""), tags=allowed_tags, attributes=allowed_atributes)
    rendered = markdown.markdown(md)
    username = current_user.id
    encrypt_flag = bleach.clean(request.form.get("Encrypt"))
    public_flag = bleach.clean(request.form.get("Public"))
    password = bleach.clean(request.form.get("encryption_password"))
    password_rep = bleach.clean(request.form.get("rewrite_encryption_password"))
    tmp = bleach.clean(request.form.get("decryption_password"))

    if tmp != "":
        global key
        key = tmp
        return redirect('/hello')
    if encrypt_flag is None:
        encrypt_flag = 0
    else:
        encrypt_flag = 1

    if public_flag is None:
        public_flag = 0
    else:
        public_flag = 1

    if encrypt_flag == 1 & public_flag == 1:
        return "Nie można udostępnić tajnej notatki", 401

    if encrypt_flag == 1:
        if checkpasswordrequirements(password):
            if password == password_rep:
                str = ""            #najgłupsza rzecz jaką widziałem do tej pory w pythonie
                str = rendered
                rendered = encode(str, password)
            else:
                return "Encryption keys are not the same", 401
        else:
            return "Password dont consist small and big letters, special character or number or isn't at least 16 characters long", 401

    db = sqlite3.connect(DATABASE)
    sql = db.cursor()

    if not isinstance(rendered, bytes):
        rendered = rendered.encode()

    sql.execute(
        f"INSERT INTO notes (username, note, is_public, is_encrypted) VALUES (?, ?, ?, ?)",
        (username, sqlite3.Binary(rendered), public_flag, encrypt_flag)
    )
    db.commit()
    db.close()

    return render_template("markdown.html", rendered=rendered)


@app.route("/render/<rendered_id>")
@login_required
def render_old(rendered_id):
    db = sqlite3.connect(DATABASE)
    sql = db.cursor()
    sql.execute(f"SELECT username, note, is_public, is_encrypted FROM notes WHERE id = {rendered_id}")
    sleep(1)
    try:
        username, rendered, is_public, is_encrypted = sql.fetchone()
        print(username, rendered, is_public, is_encrypted)
        print(1, rendered)
        if username != current_user.id and is_public == 0:
            return "Access to note forbidden", 403
        if is_encrypted == 1:
            rendered = decode_with_salt(rendered)
            print(2, rendered)
        else:
            rendered = rendered.decode()
        print(3, rendered)
        return render_template("markdown.html", rendered=str(rendered))
    finally:
        db.close()


def decode_with_salt(encoded_text):
    key = "1234!@#$qwerQWER"
    decrypt_key = PBKDF2(key, b"salt")
    nonce = encoded_text[-16:]
    cipher = AES.new(decrypt_key, AES.MODE_EAX, nonce=nonce)
    dec_text = cipher.decrypt(encoded_text[:-16])
    print("test", dec_text)
    return dec_text.decode()


if __name__ == "__main__":
    print("[*] Init database!")
    db = sqlite3.connect(DATABASE)
    sql = db.cursor()
    sql.execute("DROP TABLE IF EXISTS user;")
    sql.execute(
        "CREATE TABLE user (username VARCHAR(32), password VARCHAR(128), created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);")
    sql.execute("DELETE FROM user;")
    sql.execute(
        "INSERT INTO user (username, password) VALUES ('bach', '$5$rounds=535000$ZJ4umOqZwQkWULPh$LwyaABcGgVyOvJwualNZ5/qM4XcxxPpkm9TKh4Zm4w4');")
    sql.execute(
        "INSERT INTO user (username, password) VALUES ('john', '$5$rounds=535000$AO6WA6YC49CefLFE$dsxygCJDnLn5QNH/V8OBr1/aEjj22ls5zel8gUh4fw9');")
    sql.execute(
        "INSERT INTO user (username, password) VALUES ('bob', '$5$rounds=535000$.ROSR8G85oGIbzaj$u653w8l1TjlIj4nQkkt3sMYRF7NAhUJ/ZMTdSPyH737');")

    sql.execute("DROP TABLE IF EXISTS notes;")
    sql.execute(
        "CREATE TABLE notes (id INTEGER PRIMARY KEY, username VARCHAR(32), note BLOB, is_public bit, is_encrypted bit, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);")
    sql.execute("DELETE FROM notes;")
    sql.execute("INSERT INTO notes (username, note, id) VALUES ('bob', 'To jest sekret!', 1);")
    db.commit()
    db.close()

    app.run("0.0.0.0", 5000)
