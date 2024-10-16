from quart import Quart, request, jsonify
from quart_cors import cors
from motor.motor_asyncio import AsyncIOMotorClient
import bcrypt
from datetime import datetime, timedelta
import jwt
from secrets import token_hex, token_urlsafe
from functools import wraps
from bson import ObjectId
import re
app = Quart(__name__)
app = cors(app)
SECRET_KEY = token_hex(32)
app.config['SECRET_KEY'] = SECRET_KEY
MONGODB_URI = "mongodb://localhost:27017"
DB_NAME = "bible_db"
API_PREFIX = '/api/v1'
client = None
collection = None
blacklist_collection = None

@app.before_serving
async def connect_to_db():
    global client, collection, blacklist_collection
    try:
        client = AsyncIOMotorClient(
            MONGODB_URI,
            username="bible_user",
            password="bible_password",
            authSource=DB_NAME,
            serverSelectionTimeoutMS=5000
        )
        await client.admin.command('ping')
        db = client[DB_NAME]
        collection = db.users
        blacklist_collection = db.blacklisted_tokens
        await collection.create_index("username", unique=True)
        await collection.create_index("email", unique=True)
        await blacklist_collection.create_index("token", unique=True)
        await blacklist_collection.create_index("expiry", expireAfterSeconds=0)
        print("Connected to MongoDB successfully!")
    except Exception as e:
        print(f"MongoDB connection error: {str(e)}")
        raise

@app.after_serving
async def close_db_connection():
    if client:
        client.close()
        print("Closed MongoDB connection.")

async def is_token_blacklisted(token):
    return await blacklist_collection.find_one({"token": token}) is not None
def token_required(f):
    @wraps(f)
    async def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
          
            if token.startswith('Bearer '):
                token = token[7:]
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            print(f"Token decoded successfully: {data}")  # Debug print
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError as e:
            print(f"Token validation error: {str(e)}")  # Debug print
            return jsonify({'message': 'Token is invalid!'}), 401
        return await f(*args, **kwargs)
    return decorated

@app.route(f'{API_PREFIX}/register', methods=['POST'])
async def register():
    data = await request.get_json()
    
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not username or not email or not password:
        return jsonify({"msg": "Missing username, email or password"}), 400

    try:
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        user = {
            "username": username,
            "email": email.lower(),
            "password": hashed_password,
            "created_at": datetime.utcnow()
        }
        await collection.insert_one(user)
        return jsonify({"msg": "User registered successfully"}), 201
    except Exception as e:
        return jsonify({"msg": f"An error occurred: {str(e)}"}), 500

@app.route(f'{API_PREFIX}/login', methods=['POST'])
async def login():
    data = await request.get_json()
    
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not (username or email) or not password:
        return jsonify({"msg": "Missing username/email or password"}), 400

    user = await collection.find_one({
        "$or": [
            {"username": username},
            {"email": email.lower() if email else None}
        ]
    })

    if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
    
        await collection.update_one(
            {"_id": user["_id"]},
            {"$set": {"last_login": datetime.utcnow()}}
        )
        token = jwt.encode({
            'user_id': str(user['_id']),
            'exp': datetime.utcnow() + timedelta(hours=24)
        }, app.config['SECRET_KEY'])

        return jsonify({
            'token': token,
            'user': {
                'username': user['username'],
                'email': user['email'],
                'created_at': user['created_at'].isoformat(),
                'last_login': user.get('last_login', datetime.utcnow()).isoformat()
            }
        }), 200
    
    return jsonify({"msg": "Invalid username/email or password"}), 401
@app.route(f'{API_PREFIX}/logout', methods=['POST'])
@token_required
async def logout():
    token = request.headers.get('Authorization')
    print(f"Received token: {token}")  # Debug print
    try:
        if token.startswith('Bearer '):
            token = token[7:]
        await blacklist_collection.insert_one({
            "token": token,
            "expiry": datetime.utcnow() + timedelta(hours=24)
        })
        return jsonify({"msg": "Successfully logged out"}), 200
    except Exception as e:
        print(f"Logout error: {str(e)}")  # Debug print
        return jsonify({"msg": f"An error occurred: {str(e)}"}), 500

@app.route(f'{API_PREFIX}/user', methods=['GET'])
@token_required
async def get_user_info():
    token = request.headers.get('Authorization')
    data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
    user = await collection.find_one({"_id": ObjectId(data['user_id'])})
    
    if user:
        return jsonify({
            'username': user['username'],
            'email': user['email'],
            'created_at': user['created_at'].isoformat(),
            'last_login': user.get('last_login', datetime.utcnow()).isoformat()
        }), 200
    else:
        return jsonify({"msg": "User not found"}), 404

@app.route(f'{API_PREFIX}/reset-password', methods=['POST'])
async def reset_password():
    data = await request.get_json()
    email = data.get('email')

    if not email:
        return jsonify({"msg": "Email is required"}), 400

    if not validate_email(email):
        return jsonify({"msg": "Invalid email address"}), 400

    user = await collection.find_one({"email": email.lower()})
    if not user:
        return jsonify({"msg": "No account found with this email address"}), 404
    reset_token = token_urlsafe(32)
    expiration_time = datetime.utcnow() + timedelta(hours=1)
    await collection.update_one(
        {"_id": user["_id"]},
        {"$set": {
            "reset_token": reset_token,
            "reset_token_expires": expiration_time
        }}
    )
    reset_link = f"https://yourdomain.com/reset-password?token={reset_token}"
    return jsonify({
        "msg": "Password reset link has been sent to your email",
        "reset_link": reset_link 
    }), 200

@app.route(f'{API_PREFIX}/reset-password/confirm', methods=['POST'])
async def confirm_reset_password():
    data = await request.get_json()
    token = data.get('token')
    new_password = data.get('new_password')

    if not token or not new_password:
        return jsonify({"msg": "Token and new password are required"}), 400
    is_valid, msg = validate_password(new_password)
    if not is_valid:
        return jsonify({"msg": msg}), 400

    user = await collection.find_one({
        "reset_token": token,
        "reset_token_expires": {"$gt": datetime.utcnow()}
    })

    if not user:
        return jsonify({"msg": "Invalid or expired reset token"}), 400
    hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
    await collection.update_one(
        {"_id": user["_id"]},
        {
            "$set": {"password": hashed_password},
            "$unset": {"reset_token": "", "reset_token_expires": ""}
        }
    )

    return jsonify({"msg": "Password has been reset successfully"}), 200

def validate_email(email):
    regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(regex, email) is not None

def validate_password(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r"\d", password):
        return False, "Password must contain at least one digit"
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"
    return True, "Password is valid"

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5005)