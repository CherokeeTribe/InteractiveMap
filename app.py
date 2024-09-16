from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# Setup Flask-Login
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

# User model for Flask-Login
class User(UserMixin):
    def __init__(self, id, username, is_admin=False):
        self.id = id
        self.username = username
        self.is_admin = is_admin

@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT id, username FROM users WHERE id = ?', (user_id,))
    user = c.fetchone()
    conn.close()
    if user:
        is_admin = user[1] == 'Hokee'
        return User(user[0], user[1], is_admin)
    return None

# Initialize the user database
def init_user_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

# Initialize the pins database
def init_pins_db():
    conn = sqlite3.connect('pins.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS pins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            x INTEGER NOT NULL,
            y INTEGER NOT NULL,
            note TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            type TEXT DEFAULT 'default'
        )
    ''')
    conn.commit()
    conn.close()

# Registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        try:
            c.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
            conn.commit()
            flash('Registration successful! You can now log in.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists.')
            return redirect(url_for('register'))
        finally:
            conn.close()
    return render_template('register.html')

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('SELECT id, password FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user[1], password):
            user_obj = User(user[0], username, username == 'Hokee')
            login_user(user_obj)
            flash('Logged in successfully!')
            return redirect(url_for('map'))
        else:
            flash('Invalid credentials')
            return redirect(url_for('login'))
    
    return render_template('login.html')

# Logout route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('map'))

# Route for rendering the interactive map
@app.route('/')
def map():
    return render_template('index.html')

# Add pin with user authentication (with pin type)
@app.route('/add_pin', methods=['POST'])
@login_required
def add_pin():
    data = request.get_json()
    x = data['x']
    y = data['y']
    note = data['note']
    pin_type = data.get('type', 'default')  # Default type if not provided
    
    conn = sqlite3.connect('pins.db')
    c = conn.cursor()
    c.execute('INSERT INTO pins (x, y, note, user_id, type) VALUES (?, ?, ?, ?, ?)', 
              (x, y, note, current_user.id, pin_type))
    conn.commit()
    conn.close()
    
    return jsonify({'status': 'success'}), 201

# Get all pins (publicly available)
@app.route('/get_pins', methods=['GET'])
def get_pins():
    filter_by_user = request.args.get('filter') == 'my_pins'
    
    conn = sqlite3.connect('pins.db')
    c = conn.cursor()
    
    if filter_by_user and current_user.is_authenticated:
        c.execute('SELECT x, y, note, user_id, id, type FROM pins WHERE user_id = ?', (current_user.id,))
    else:
        c.execute('SELECT x, y, note, user_id, id, type FROM pins')
    
    pins = [{'x': row[0], 'y': row[1], 'note': row[2], 'user_id': row[3], 'id': row[4], 'type': row[5]} for row in c.fetchall()]
    conn.close()
    
    return jsonify(pins)

# Edit pin (only by owner or admin)
@app.route('/edit_pin/<int:pin_id>', methods=['POST'])
@login_required
def edit_pin(pin_id):
    data = request.get_json()
    new_note = data['note']
    
    conn = sqlite3.connect('pins.db')
    c = conn.cursor()
    c.execute('SELECT user_id FROM pins WHERE id = ?', (pin_id,))
    pin = c.fetchone()
    
    if pin and (pin[0] == current_user.id or current_user.is_admin):
        c.execute('UPDATE pins SET note = ? WHERE id = ?', (new_note, pin_id))
        conn.commit()
        conn.close()
        return jsonify({'status': 'success'}), 200
    conn.close()
    return jsonify({'status': 'error', 'message': 'Not authorized to edit this pin'}), 403

# Delete pin (only by owner or admin)
@app.route('/delete_pin/<int:pin_id>', methods=['POST'])
@login_required
def delete_pin(pin_id):
    conn = sqlite3.connect('pins.db')
    c = conn.cursor()
    c.execute('SELECT user_id FROM pins WHERE id = ?', (pin_id,))
    pin = c.fetchone()
    
    if pin and (pin[0] == current_user.id or current_user.is_admin):
        c.execute('DELETE FROM pins WHERE id = ?', (pin_id,))
        conn.commit()
        conn.close()
        return jsonify({'status': 'success'}), 200
    conn.close()
    return jsonify({'status': 'error', 'message': 'Not authorized to delete this pin'}), 403

if __name__ == '__main__':
    init_user_db()  # Initialize the user database
    init_pins_db()  # Initialize the pins database
    app.run(debug=True)
