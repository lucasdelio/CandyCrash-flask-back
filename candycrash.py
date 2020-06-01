from flask import Flask, request, make_response, abort
import pymongo
from bson import json_util
import json
from datetime import datetime, timedelta
from flask_cors import CORS, cross_origin
from cryptography.fernet import Fernet
from apscheduler.schedulers.background import BackgroundScheduler
import requests
import random

GOOGLE_USER_INFO_URL = 'https://openidconnect.googleapis.com/v1/userinfo'
SIGNUP_INVITATION_URL = 'http://localhost:3000/signup/'
JSON_HEADER = {'content-type':'application/json'}
TTL_ = 24*60*60 #24 hs ttl for generated tokens
SPARK_TOKEN_COOKIE_NAME = 'sessionToken-Spark'
GUEST_TOKEN_COOKIE_NAME = 'sessionToken-Guest'

app = Flask(__name__)
CORS(app)
file = open('key.key', 'rb')
key = file.read() # The key will be type bytes
ferne = Fernet(key)
file.close()

client = pymongo.MongoClient('mongodb://localhost:27017/')
db = client.test_database
users_collection = db.users_collection
#make user, email and invitation-token unique
users_collection.create_index([('user', pymongo.ASCENDING)], unique=True)
users_collection.create_index([('invitation-token', pymongo.ASCENDING)], unique=True)

def deleteExpiredUsersTask():
    for p in users_collection.find():
        t = p['invitation-token']
        if not isValidToken(t):
            users_collection.delete_one(p)
            
scheduler = BackgroundScheduler()
scheduler.add_job(func=deleteExpiredUsersTask, trigger="interval", seconds=60)
scheduler.start()

''' @app.route('/users')
def personas():
    p = users_collection.find()
    return json_util.dumps(p), 200, JSON_HEADER '''
''' 
#find a user
@app.route('/user')
def findUser( ):
    u = users_collection.find_one( {'user': 'lucasdelio'} )
    if u:
        return json_util.dumps(u),200, JSON_HEADER
    else:
        return '',204 #204 = no content '''

def getAllEvents():
    with open('events.json') as json_file:
        return json.load(json_file)
        
@app.route('/events') #return 15 events with rotation every 2 hours
def allEvents():
    events = getAllEvents()
    hours = datetime.utcnow().strftime("%H")
    shift = int(hours)//2 # // operator returs the floor of the division :D
    subselectedEvents = events[ shift :shift+15]
    return json.dumps(subselectedEvents),200, JSON_HEADER
    
@app.route('/event/<string:id>')
def searchEvent(id):
    events = getAllEvents()
    l = [ e for e in events if e['id'] == id ]
    if not l :
        return '',204 #204 no content
    e = l[0]
    e['time'] = str(datetime.utcnow()+timedelta(hours= random.randrange(100)) )
    return e,200, JSON_HEADER

def isSessionActive(request):
    token = request.cookies.get( SPARK_TOKEN_COOKIE_NAME )
    return isValidToken(token)

''' @app.route('/alive',methods=['GET'])
def alive():
    if not isSessionActive(request):
        return '',401
    return '',200 '''

@app.route('/generate-invitation',methods=['POST'])
@cross_origin(supports_credentials=True)
def generateInvitation2():
    if not isSessionActive(request):
        return '',401
    try: # try to create a dict to check if the cfg is correct
        cfg = json.loads( request.data.decode('utf8')  ) 
    except:
        return 'Invalid json body',400 
    encrypted = ferne.encrypt( request.data ).decode('utf8')
    return SIGNUP_INVITATION_URL+ encrypted

def isValidToken(token):
    try:
        dec = ferne.decrypt( bytes(token, 'utf8'), ttl= TTL_ )
    except:
        return False
    return dec

@app.route('/signup-guest',methods=['POST'])
def signupGuest():
    try:
        data = request.get_json() or request.form
        user = data['user']
        email = data['email']
        password = data['password']
        token = data['invitation-token']
    except: #if the token is invalid then 401 (Unauthorized)
        return 'Invalid parameters',401
    if not isValidToken(token):
        return 'Invalid token',401
    try:
        users_collection.insert_one({
            'user' : user,
            'email' : email,
            'password' : password,
            'invitation-token': token
        })
    except:  #409 http = conflict
        return 'User already in use',409
    return '',201

@app.route("/login-guest", methods=['POST'])
@cross_origin(supports_credentials=True)
def loginGuest():
    try:
        data = request.get_json() or request.form
        user = data['user']
        password = data['password']
    except: #return 400, bad request
        return '',400
    u = users_collection.find_one( {'user': user} )
    if not u:
        return 'user not found', 401
    if not password == u['password']:
        return 'bad password', 401
    userCfg = isValidToken( u['invitation-token'] )
    if not userCfg:
        return 'user invitation time expired', 401
    r = {
        'user' : user,
        'config' : json.loads( userCfg.decode('utf8') )
    }
    resp = make_response( r, 200, JSON_HEADER )
    resp.set_cookie(GUEST_TOKEN_COOKIE_NAME, ferne.encrypt(b'asdf').decode('utf8'), max_age=60*60) #expires in 1 hour
    return resp

@app.route("/logout-guest", methods=['POST'])
@cross_origin(supports_credentials=True)
def logoutGuest():
    resp = make_response( '', 200 )
    resp.set_cookie(GUEST_TOKEN_COOKIE_NAME, expires=0)
    return resp

@app.route("/login-spark", methods=['POST'])
@cross_origin(supports_credentials=True)
def loginSpark():
    data = request.get_json() or request.form
    accessToken = data.get('accessToken')
    if not accessToken:
        return 'missing accessToken',401
    headers = {"Authorization": 'Bearer '+accessToken}
    json = requests.post( GOOGLE_USER_INFO_URL, headers=headers).json()
    if not json.get('email'):
        return '',401
    resp = make_response( json, 200 , JSON_HEADER )
    resp.set_cookie(SPARK_TOKEN_COOKIE_NAME, ferne.encrypt(b'asdf').decode('utf8'), max_age=TTL_) #expires in one day
    return resp

if __name__ == '__main__':
    app.run(debug=True)