
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_uploads import UploadSet, configure_uploads, IMAGES, DOCUMENTS
from werkzeug.utils import secure_filename
from werkzeug.datastructures import  FileStorage

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'

app.config['UPLOADED_FILES_DEST'] = 'uploads'
bcrypt = Bcrypt(app)
db = SQLAlchemy(app)
files = UploadSet('files', DOCUMENTS)
configure_uploads(app, files)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    is_ops_user = db.Column(db.Boolean, default=False)


class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


@app.route('/ops_user/register', methods=['POST'])
def ops_user_register():
    data = request.get_json()
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_user = User(username=data['username'], email=data['email'], password=hashed_password, is_ops_user=True)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'Ops User registered successfully'})

@app.route('/ops_user/login', methods=['POST'])
def ops_user_login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    if user and bcrypt.check_password_hash(user.password, data['password']):
       
        return jsonify({'message': 'Ops User logged in successfully'})
    else:
        return jsonify({'message': 'Login failed. Check your username and password'})

@app.route('/ops_user/upload_file', methods=['POST'])
def ops_user_upload_file():
    if 'file' not in request.files:
        return jsonify({'message': 'No file part'})
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'message': 'No selected file'})

    if file and files.file_allowed(file, file.filename):
        
        filename = files.save(file)
        new_file = File(filename=filename, user_id=current_user.id)
        db.session.add(new_file)
        db.session.commit()
        return jsonify({'message': 'File uploaded successfully'})
    else:
        return jsonify({'message': 'File type not allowed'})

def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/client_user/signup', methods=['POST'])
def client_user_signup():
    data = request.get_json()
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_user = User(username=data['username'], email=data['email'], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'Client User registered successfully'})

@app.route('/client_user/login', methods=['POST'])
def client_user_login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    if user and bcrypt.check_password_hash(user.password, data['password']):
        login_user(user)
        return jsonify({'message': 'Client User logged in successfully'})
    else:
        return jsonify({'message': 'Login failed. Check your username and password'})

@app.route('/client_user/logout')
@login_required
def client_user_logout():
    logout_user()
    return jsonify({'message': 'Client User logged out successfully'})





if __name__ == '__main__':
    app.run(debug=True)