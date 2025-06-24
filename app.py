from flask import Flask, render_template, request, redirect, session, url_for, send_file
from flask_bcrypt import Bcrypt
from pymongo import MongoClient
from encryption import encrypt_file, decrypt_file
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'
bcrypt = Bcrypt(app)

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# MongoDB setu
client = MongoClient(os.environ.get("MONGO_URI"))

users = db["users"]
files = db["files"]

# Routes
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        if users.find_one({'email': email}):
            return "Email already registered"
        users.insert_one({'username': username, 'email': email, 'password': password})
        return redirect('/login')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = users.find_one({'username': request.form['username']})
        if user and bcrypt.check_password_hash(user['password'], request.form['password']):
            session['user_id'] = str(user['_id'])
            session['username'] = user['username']
            return redirect('/dashboard')
        return "Invalid credentials"
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/login')
    return render_template('dashboard.html', username=session['username'])

@app.route('/upload', methods=['POST'])
def upload():
    if 'user_id' not in session:
        return redirect('/login')
    file = request.files['file']
    key = request.form['key'].encode()
    encrypted_data = encrypt_file(file.read(), key)
    path = os.path.join(UPLOAD_FOLDER, file.filename)
    with open(path, 'wb') as f:
        f.write(encrypted_data)
    files.insert_one({'filename': file.filename, 'path': path, 'user_id': session['user_id']})
    return redirect('/files')

@app.route('/files')
def file_list():
    if 'user_id' not in session:
        return redirect('/login')
    user_files = list(files.find({'user_id': session['user_id']}))
    return render_template('files.html', files=user_files)

@app.route('/download/<filename>', methods=['GET', 'POST'])
def download(filename):
    if request.method == 'POST':
        key = request.form['key'].encode()
        path = os.path.join(UPLOAD_FOLDER, filename)
        with open(path, 'rb') as f:
            encrypted_data = f.read()
        decrypted_data = decrypt_file(encrypted_data, key)
        decrypted_path = os.path.join(UPLOAD_FOLDER, f'decrypted_{filename}')
        with open(decrypted_path, 'wb') as df:
            df.write(decrypted_data)
        return send_file(decrypted_path, as_attachment=True)
    return '''
        <form method="POST">
            <input type="password" name="key" required placeholder="Enter decryption key">
            <input type="submit" value="Download & Decrypt">
        </form>
    '''
@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        username = request.form['username']
        new_password = request.form['new_password']

        user = users.find_one({'username': username})
        if not user:
            return render_template('error.html')

        users.update_one({'username': username}, {'$set': {'password': new_password}})
        return redirect(url_for('login'))

    return render_template('reset_password.html')

@app.route('/chatbot')
def chatbot():
    return render_template('chatbot.html')

if __name__ == '__main__':
    app.run(debug=True)
