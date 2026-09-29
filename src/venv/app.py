import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, flash, session

app = Flask(__name__)
app.secret_key = 'super-secret-key-change-me'
DB_NAME = 'users.db'

def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# Страница входа доступна и по главному адресу, и по адресу /login
@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'username' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        from werkzeug.security import check_password_hash
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['username'] = user['username']
            session['email'] = user['email']
            return redirect(url_for('dashboard'))
        else:
            flash('Неверный Email или пароль.', 'error')
            return render_template('login.html')
            
    return render_template('login.html')

# Титульная страница (Личный кабинет)
@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        flash('Пожалуйста, сначала войдите в аккаунт.', 'error')
        return redirect(url_for('login'))
        
    return render_template('dashboard.html', username=session['username'])

# Выход из аккаунта
@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('email', None)
    flash('Вы успешно вышли из системы.', 'success')
    return redirect(url_for('login'))

# Страница регистрации
@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'username' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm-password')
        
        if password != confirm_password:
            flash('Ошибка: Пароли не совпадают!', 'error')
            return render_template('register.html')
            
        from werkzeug.security import generate_password_hash
        conn = get_db_connection()
        existing_user = conn.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone()
        
        if existing_user:
            flash('Ошибка: Пользователь с таким Email уже зарегистрирован!', 'error')
            conn.close()
            return render_template('register.html')
            
        hashed_password = generate_password_hash(password)
        try:
            conn.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
                         (username, email, hashed_password))
            conn.commit()
            flash(f'Успех! Аккаунт {username} создан. Теперь вы можете войти.', 'success')
            return redirect(url_for('login'))
        except sqlite3.Error as e:
            flash(f'Произошла ошибка при сохранении: {e}', 'error')
        finally:
            conn.close()
        
    return render_template('register.html')

if __name__ == '__main__':
    app.run(debug=True)