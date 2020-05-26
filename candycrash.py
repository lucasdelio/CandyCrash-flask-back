from flask import Flask, request
import pymongo
from bson import json_util
import json
from datetime import datetime, timedelta
import base64
from flask_cors import CORS
from cryptography.fernet import Fernet

app = Flask(__name__)
CORS(app)
file = open('key.key', 'rb')
key = file.read() # The key will be type bytes
file.close()

client = pymongo.MongoClient('mongodb://localhost:27017/')
db = client.test_database
users_collection = db.users_collection
#make user, email and invitation-token unique
users_collection.create_index([('user', pymongo.ASCENDING)], unique=True)
users_collection.create_index([('email', pymongo.ASCENDING)], unique=True)
users_collection.create_index([('invitation-token', pymongo.ASCENDING)], unique=True)

@app.route('/users')
def personas():
    p = users_collection.find()
    return json_util.dumps(p),200,{'content-type':'application/json'}

#find a user
@app.route('/user')
def findUser( ):
    u = users_collection.find_one( {'user': 'lucasdelio'} )
    if u:
        return json_util.dumps(u),200,{'content-type':'application/json'}
    else:
        return '',204 #204 = no content

def getAllEvents():
    with open('events.json') as json_file:
        return json.load(json_file)
        
@app.route('/events') #return 15 events with rotation every 2 hours
def allEvents():
    events = getAllEvents()
    hours = datetime.utcnow().strftime("%H")
    shift = int(hours)//2 # // operator returs the floor of the division :D
    subselectedEvents = events[ shift :shift+15]
    return json.dumps(subselectedEvents),200,{'content-type':'application/json'}
    
@app.route('/event/<string:id>')
def searchEvent(id):
    events = getAllEvents()
    l = [ e for e in events if e['id'] == id ]
    return json.dumps(l),200,{'content-type':'application/json'}

@app.route('/generate-invitation',methods=['POST'])
def generateInvitation2():
    try:
        # request.data returns is the POST body in bytes
        # then decode it to string and create a dict
        cfg = json.loads( request.data.decode('utf8')  ) 
    except:
        return 'Invalid json body',400 
    object = {
       "expiration-date" : str(datetime.utcnow()+timedelta(hours=24)), #expires in 24 hours
       "user-config" : cfg
    }
    #dict to string and then string to bytes
    message = bytes( json.dumps(object), 'utf8')
    #encrypt from bytes to bytes
    encrypted = Fernet(key).encrypt(message)
    #base64 encode in bytes, then bytes to string
    base64invite = base64.b64encode( encrypted ).decode('utf8')
    return 'http://localhost:3000/register/'+ base64invite

def isValidToken(token):
    try:
        b64 = base64.b64decode(token)
        decbytes = Fernet(key).decrypt(b64)
        decStr = decbytes.decode('utf8')
        dict = json.loads( decStr)
        if dict["expiration-date"] > str(datetime.utcnow()):
            return 200
        else:  
            return 406
    except:
        return 401 #if the token is invalid then 401 (Unauthorized)

@app.route('/verify-registration-token/<string:token>',methods=['GET'])
def verifyRegistrationToken(token):
    code = isValidToken(token)
    if code==200:
        return 'Token is valid',200    
    if code==406:
        return 'Token duration expired',406
    return 'Invalid token',401

@app.route('/register',methods=['POST'])
def register():
    try:
        data = request.get_json() or request.form
        user = data['user']
        email = data['email']
        password = data['password']
        token = data['invitation-token']
    except:
        #if the token is invalid then 401 (Unauthorized)
        return 'Invalid parameters',401
    code = isValidToken(token)
    if   code==401:
        return 'Invalid token',401
    elif code==406:
        return 'Invitation token expired',406
    elif code==200:
        try:
            users_collection.insert_one({
                'user' : user,
                'email' : email,
                'password' : password,
                'invitation-token': token
            })
        except:
            #if the token is invalid then 401 (Conflict)
            return 'User already in use',409
        return '',201


if __name__ == '__main__':
    app.run(debug=True)