from flask import Flask, request, make_response, abort
import pymongo
from bson import json_util
import json
from datetime import datetime, timedelta
from flask_cors import CORS, cross_origin
from cryptography.fernet import Fernet
from apscheduler.schedulers.background import BackgroundScheduler
import requests
import base64
import random

#SIGNUP_INVITATION_URL = 'http://localhost:3000/invitation/'
SIGNUP_INVITATION_URL = 'https://candicrash.sparkdigital.rocks/invitation/'
GOOGLE_USER_INFO_URL = 'https://openidconnect.googleapis.com/v1/userinfo'
JSON_HEADER = {'content-type':'application/json'}
TTL_ = 24*60*60 #24 hs ttl for generated tokens
SPARK_TOKEN_COOKIE_NAME = 'sessionToken-Spark'
GUEST_TOKEN_COOKIE_NAME = 'sessionToken-Guest'

app = Flask(__name__)
CORS(app)

#generate a new key file
#key = Fernet.generate_key()
#file = open('key.key', 'wb')
#file.write(key) # The key is type bytes still
#file.close()

file = open('key.key', 'rb')
key = file.read() # The key will be type bytes
ferne = Fernet(key)
file.close()

client = pymongo.MongoClient('mongodb://localhost:27017/')
db = client.test_database
users_collection = db.users_collection
admins_collection = db.admins_collection
#make user, email and invitation-token unique
users_collection.create_index([('user', pymongo.ASCENDING)], unique=True)
users_collection.create_index([('invitation-token', pymongo.ASCENDING)], unique=True)
admins_collection.create_index([('email', pymongo.ASCENDING)], unique=True)

def deleteExpiredUsersTask():
    for p in users_collection.find():
        t = p['invitation-token']
        if not isValidToken(t):
            users_collection.delete_one(p)
            
scheduler = BackgroundScheduler()
scheduler.add_job(func=deleteExpiredUsersTask, trigger="interval", seconds=60)
scheduler.start()

@app.route('/users')
def personas():
    p = users_collection.find()
    return json_util.dumps(p), 200, JSON_HEADER

''' @app.route('/user') #find a user
def findUser( ):
    u = users_collection.find_one( {'user': 'lucasdelio'} )
    if u:
        return json_util.dumps(u),200, JSON_HEADER
    else:
        return '',204 #204 = no content '''

def getAllEvents():
    with open('events.json') as json_file:
        events = json.load(json_file)
        for e in events:
            desc = e['description']
            mod15 = ( ord(desc[0])+ord(desc[1])+ord(desc[2]) ) % 15;
            e['time'] = str(datetime.utcnow()+timedelta(hours= mod15*24) )
        return events

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
    return e,200, JSON_HEADER

def isSessionActive(request):
    token = request.cookies.get( SPARK_TOKEN_COOKIE_NAME )
    return isValidToken(token)

@app.route('/generate-invitation',methods=['POST'])
@cross_origin(supports_credentials=True)
def generateInvitation2():
    if not isSessionActive(request):
        return '',401
    try: #request.data is the body with the bugs configuration
        cfg = json.loads( request.data.decode('utf8')  ) 
    except:
        return 'Invalid json body',400 
    cfg['invitation-token'] = ferne.encrypt( request.data ).decode('utf8')
    invitationBase64 = base64.b64encode( bytes(json.dumps(cfg) , 'utf8')).decode('utf8')
    return SIGNUP_INVITATION_URL+ invitationBase64

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
            'invitation-token': token,
            #decrit de token with the raw config and encode in base64
            'bugs-config': base64.b64encode(ferne.decrypt(bytes(token,'utf8'))).decode('utf8')
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
    if not isValidToken( u['invitation-token'] ):
        return 'user invitation time expired', 401
    resp = make_response( json_util.dumps(u), 200, JSON_HEADER )
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

@app.route("/admins", methods=['GET','POST','DELETE'])
@cross_origin(supports_credentials=True)
def admins_():
    #if not isSessionActive(request): return '',401 #is no admin login cookie
    email = request.args.get('email')
    if request.method == 'POST':
        if not email: return 'no email param',400
        try: admins_collection.insert_one( {'email':email } )
        except: pass
    if request.method == 'DELETE':
        if not email: return 'no email param',400
        admins_collection.delete_one( {'email':email } )
    admins = json_util.dumps( admins_collection.find() )
    return admins, 200, JSON_HEADER

if __name__ == '__main__':
    app.run(debug=True)