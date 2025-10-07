from flask import Flask, request, jsonify
import jwt
import datetime
import os
import html
from models import db, User

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('JWT_SECRET', 'super-secret-key-for-dev-only')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

def create_tables():
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin')
        admin.set_password('securepassword123')
        db.session.add(admin)
        db.session.commit()

@app.route('/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    user = User.query.filter_by(username=username).first()
    if user and user.check_password(password):
        token = jwt.encode({
            'user': username,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        }, app.config['SECRET_KEY'], algorithm='HS256')
        return jsonify({"token": token}), 200
    else:
        return jsonify({"error": "Invalid credentials"}), 401

@app.route('/api/data', methods=['GET'])
def get_data():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({"error": "Token required"}), 401

    try:
        decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        return jsonify({
            "message": f"Hello, {decoded['user']}",
            "data": ["item1", "item2", "confidential_info"]
        }), 200
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401

@app.route('/api/comments', methods=['POST'])
def add_comment():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({"error": "Authentication required"}), 401

    try:
        jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401

    comment = request.get_json().get('comment')
    if not comment:
        return jsonify({"error": "Comment text required"}), 400

    # Защита от XSS
    safe_comment = html.escape(comment)

    return jsonify({"status": "Comment added", "comment": safe_comment}), 201

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin')
            admin.set_password('securepassword123')
            db.session.add(admin)
            db.session.commit()
    app.run(debug=False, host='127.0.0.1', port=5000)