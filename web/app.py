from asyncio import subprocess
from flask import Flask, jsonify, request, render_template
from flask_restful import Api, Resource

from pymongo import MongoClient
from debugger import initialize_debugger

import bcrypt
import requests
import os

from image_classification import predict

app = Flask(__name__)
app.config.from_object('config.DevelopmentConfig')
api = Api(app)

client = MongoClient(app.config['DATABASE'])  # same name in docker compose
db = client.SentenceDatabase
users = db["Users"]
admin = db["Admin"]


@app.route('/')
def hello_word():
    return render_template('index.html')


def set_admin_in_db():
    try:
        admin_username = app.config['ADMIN_USERNAME']
        admin.find({"Admin": admin_username})[0]['Admin']
    except Exception as e:
        admin.delete_many({})
        hashed_password = bcrypt.hashpw(app.config['ADMIN_PASSWORD'], bcrypt.gensalt())
        admin.insert_one(
            {
                "Admin": app.config['ADMIN_USERNAME'],
                "Password": hashed_password
            }
        )
        print('Set Admin sucessfully!')


def get_username_data():
    dict_resp = {
        'status_code': 200,
        'message': 'Ok'
    }

    try:
        post_data = request.get_json()

        dict_resp['username'] = post_data["username"]
        dict_resp['password'] = post_data["password"]

    except Exception as e:
        dict_resp = {
        'status_code': 305,
        'message': str(e)
        }

    return dict_resp


def get_data_admin():
    dict_resp = {
        'status_code': 200,
        'message': 'Ok'
    }

    try:
        post_data = request.get_json()

        dict_resp['username'] = str(post_data["username"])
        dict_resp['admin_username'] = str(post_data["admin_username"])
        dict_resp['admin_password'] = str(post_data["admin_password"])
        dict_resp['refil_tokens'] = int(post_data["refil_tokens"])
    except Exception as e:
        dict_resp = {
        'status_code': 305,
        'message': str(e)
        }
    
    return dict_resp


def user_already_exist(username):
    try:
        if users.find({"Username": username})[0]['Username'] == username:
            return True
    except Exception as e:
        print(e)
    
    return False


def valid_user_and_passoword(username, password):
    try:
        hash_password = str(users.find({"Username": username})[0]["Password"])
        if bcrypt.hashpw(password, hash_password) == hash_password:
            return True
    except Exception as e:
        print(e)
    
    return False


def valid_admin_and_passoword(username, password):
    try:
        hash_password = str(admin.find({"Admin": username})[0]["Password"])
        if bcrypt.hashpw(password, hash_password) == hash_password:
            return True
    except Exception as e:
        print(e)
    
    return False


def get_tokens(username):
    try:
        tokens = int(users.find({"Username": username})[0]["Tokens"])
    except Exception as e:
        print(e)
        tokens = 0
    
    return tokens


def set_username_tokens(username, tokens):

    users.update_one(
        {"Username": username},
        {
            "$set": {
                "Tokens": tokens
                }
        } 
    )


def get_url_data(dict_resp):
    try:
        post_data = request.get_json()

        dict_resp['url'] = post_data["url"]
    except Exception as e:
        dict_resp['status_code'] = 305
        dict_resp['message'] = str(e)


def classify(url):
    r = requests.get(url)

    with open("temp.jpg", "wb") as f:
        f.write(r.content)
        json_classify = predict("temp.jpg")
    
    if os.path.exists("temp.jpg"):
        os.remove("temp.jpg")
    else:
        print("The file does not exist")
    
    return json_classify


class Register(Resource):
    def post(self):
        dict_resp = get_username_data()

        if dict_resp['status_code'] != 200:
            return dict_resp
        
        username = dict_resp['username']
        password = dict_resp['password']
        tokens = 5
        
        if user_already_exist(username):
            return jsonify(
                {
                    'Status Code': 301,
                    'Message': "User already exists",
                }
            )

        hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())

        users.insert_one(
            {
                "Username": username,
                "Password": hashed_password,
                "Tokens": tokens
            }
        )

        dict_resp['Tokens'] = tokens

        return jsonify(dict_resp)


class Classify(Resource):
    def post(self):
        dict_resp = get_username_data()
        get_url_data(dict_resp)

        if dict_resp['status_code'] != 200:
            return dict_resp
        
        username = dict_resp['username']
        password = dict_resp['password']
        
        if not valid_user_and_passoword(username, password):
            dict_resp['message'] = "Invalid Username or Password"
            return jsonify(dict_resp)
        
        tokens = get_tokens(username)

        if tokens < 1:
            return jsonify(
                {
                    'Status Code': 303,
                    'Message': "You dont have enouth tokens",
                }
            )
        
        try:
            dict_json = classify(dict_resp['url'])
        except Exception as e:
            print(e)
            return jsonify(
                {
                    'Status Code': 305,
                    'Message': "Sorry one internal error have ocurred",
                }
            )

        try:
            set_username_tokens(username, tokens - 1)
        except Exception as e:
            print(e)
            return jsonify(
                {
                    'Status Code': 305,
                    'Message': "Sorry one internal error have ocurred",
                }
            )

        dict_json['tokens'] = tokens - 1 

        return dict_json


class Refil(Resource):
    def post(self):
        dict_result = get_data_admin()

        if dict_result['status_code'] != 200:
            return jsonify(dict_result)
        
        username = dict_result['username']
        admin_username = dict_result['admin_username']
        admin_password = dict_result['admin_password']
        refil_tokens = dict_result['refil_tokens']

        if not user_already_exist(username):
            return jsonify(
                {
                    'Status Code': 302,
                    'Message': 'Invalid username',
                }
            )

        if not valid_admin_and_passoword(admin_username, admin_password):
            return jsonify(
                {
                    'Status Code': 303,
                    'Message': 'Invalid admin username or admin password',
                }
            )

        tokens = get_tokens(username)
        new_tokens = tokens + refil_tokens
        set_username_tokens(username, new_tokens)

        dict_result['old_tokens'] = tokens
        dict_result['new_tokens'] = new_tokens

        return jsonify(dict_result)


api.add_resource(Register, "/register")
api.add_resource(Classify, "/classify")
api.add_resource(Refil, "/refil")

if __name__ == '__main__':
    initialize_debugger()

    set_admin_in_db()

    app.run(
        host = app.config['HOST'],
        port = app.config['PORT'], 
        debug= app.config['DEBUG']
        )
