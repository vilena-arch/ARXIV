import hashlib
import secrets
from flask import Flask, render_template, request, jsonify
import mysql.connector

app = Flask(__name__)

SALT_LEN = 32  # длина соли в hex-символах (16 байт)


def get_connection():
    return mysql.connector.connect(
        host="185.114.247.43",
        port=3306,
        database="sch688_vvedenie",
        user="sch688_vvedenie",
        password="Qwerty123"
    )


def hash_password(password: str) -> str:
    """<соль><хеш>, без разделителей, только hex-символы."""
    salt = secrets.token_hex(16)              # 32 символа
    digest = hashlib.sha256((salt + password).encode('utf-8')).hexdigest()
    return salt + digest                       # всего 96 символов


def verify_password(password: str, stored: str) -> bool:
    salt = stored[:SALT_LEN]
    expected = stored[SALT_LEN:]
    digest = hashlib.sha256((salt + password).encode('utf-8')).hexdigest()
    return secrets.compare_digest(digest, expected)


# ---------- РЕГИСТРАЦИЯ ----------
@app.route('/user_register', methods=['POST'])
def user_register():
    req = request.get_json()

    name = req['name']
    login = req['email']
    password = req['password']

    password_hash = hash_password(password)

    cnx = get_connection()
    try:
        cur = cnx.cursor()

        # Проверяем, нет ли уже такого email
        cur.execute('SELECT id FROM users WHERE email = %s', (login,))
        if cur.fetchone():
            cur.close()
            return jsonify({'error': 'Пользователь с таким email уже существует'}), 409

        cur.execute(
            'INSERT INTO `users`(`username`, `email`, `password_hash`) VALUES (%s, %s, %s)',
            (name, login, password_hash)
        )
        cnx.commit()
        cur.close()
    finally:
        cnx.close()

    return jsonify({'result': True})


# ---------- АВТОРИЗАЦИЯ ----------
@app.route('/user_login', methods=['POST'])
def user_login():
    req = request.get_json()

    login = req['email']
    password = req['password']

    cnx = get_connection()
    try:
        cur = cnx.cursor()
        cur.execute(
            'SELECT id, username, password_hash FROM users WHERE email = %s',
            (login,)
        )
        row = cur.fetchone()
        cur.close()
    finally:
        cnx.close()

    if not row:
        return jsonify({'error': 'Неверный email или пароль'}), 401

    user_id, username, stored_hash = row
    if not verify_password(password, stored_hash):
        return jsonify({'error': 'Неверный email или пароль'}), 401

    return jsonify({'result': True, 'id': user_id, 'username': username})


# ---------- СТРАНИЦЫ ----------
@app.route("/")
def registration():
    return render_template('registration.html')


@app.route("/login")
def login():
    return render_template('login.html')


if __name__ == '__main__':
    app.run(debug=True)