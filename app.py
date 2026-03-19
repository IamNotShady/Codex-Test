import base64
import hashlib
import hmac
import os
from typing import Optional

import pyodbc
from flask import Flask, flash, redirect, render_template, request, url_for

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key')


def get_db_connection() -> pyodbc.Connection:
    connection_string = os.getenv(
        'SQLSERVER_CONNECTION_STRING',
        'DRIVER={ODBC Driver 18 for SQL Server};'
        'SERVER=localhost,1433;'
        'DATABASE=CodexTest;'
        'UID=sa;'
        'PWD=YourStrong!Passw0rd;'
        'TrustServerCertificate=yes;'
    )
    return pyodbc.connect(connection_string)


def hash_password(password: str, salt: bytes) -> str:
    derived_key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return base64.b64encode(derived_key).decode('utf-8')


def verify_password(password: str, salt_value: str, password_hash: str) -> bool:
    salt = base64.b64decode(salt_value)
    computed_hash = hash_password(password, salt)
    return hmac.compare_digest(computed_hash, password_hash)


def fetch_user_by_email(email: str) -> Optional[dict]:
    query = """
        SELECT TOP 1 email, password_hash, password_salt
        FROM users
        WHERE email = ?
    """

    with get_db_connection() as connection:
        cursor = connection.cursor()
        row = cursor.execute(query, email).fetchone()

    if row is None:
        return None

    return {
        'email': row.email,
        'password_hash': row.password_hash,
        'password_salt': row.password_salt,
    }


@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')

        if not email or not password:
            flash('请输入邮箱和密码。', 'error')
            return render_template('login.html', title='Login')

        try:
            user = fetch_user_by_email(email)
        except pyodbc.Error:
            flash('数据库连接失败，请稍后重试。', 'error')
            return render_template('login.html', title='Login')

        if user and verify_password(password, user['password_salt'], user['password_hash']):
            return redirect(url_for('login_success', email=user['email']))

        flash('用户名或密码不对。', 'error')

    return render_template('login.html', title='Login')


@app.route('/success')
def login_success():
    email = request.args.get('email', '')
    return render_template('success.html', title='Login success', email=email)


if __name__ == '__main__':
    app.run(debug=True)
