from datetime import datetime, timedelta
from time import mktime
from tornado.escape import json_decode, utf8
from tornado.gen import coroutine
from uuid import uuid4
import base64
import hashlib

from .base import BaseHandler

class LoginHandler(BaseHandler):

    @coroutine
    def generate_token(self, email):
        token_uuid = uuid4().hex
        expires_in = datetime.now() + timedelta(hours=2)
        expires_in = mktime(expires_in.utctimetuple())

        token = {
            'token': token_uuid,
            'expiresIn': expires_in,
        }

        yield self.db.users.update_one({
            'email': email
        }, {
            '$set': token
        })

        return token

    @coroutine
    def post(self):
        try:
            body = json_decode(self.request.body)
            email = body['email'].lower().strip()
            if not isinstance(email, str):
                raise Exception()
            password = body['password']
            if not isinstance(password, str):
                raise Exception()
        except:
            self.send_error(400, message='You must provide an email address and password!')
            return

        if not email:
            self.send_error(400, message='The email address is invalid!')
            return

        if not password:
            self.send_error(400, message='The password is invalid!')
            return

        print("FINDING USER: ", email)
        user = yield self.db.users.find_one({
          'email': email
        }, {
          'salt': 1, 
          'hash': 1, 
          'iterations': 1
        })

        if user is None:
            self.send_error(403, message='The email address and password are invalid!')
            return

        print("User found: ", email)
        print("User salt: ", user['salt'])  
        print("User pepper:", self.application.pepper.hex(), "BYTE", str(type(self.application.pepper)))      


        # Decode the stored salt from base64 to raw bytes
        stored_salt = base64.b64decode(user['salt'])
        
        # Get the stored hash and iteration count from the database
        stored_hash = user['hash']
        iterations = user['iterations']

        # Retrieve the application-wide pepper (secret value used to harden passwords)
        pepper = self.application.pepper

        # Combine the user-provided password with the pepper (in bytes)
        combined = password.encode("utf-8") + pepper 

        dk = hashlib.pbkdf2_hmac('sha256', combined, stored_salt, iterations)
        print("Stored hash:", user['hash'])
        print("Recomputed:", base64.b64encode(dk).decode())

        # Compare the computed hash with the stored hash not stred in plain text just the hash unreadable values
        if (base64.b64encode(dk).decode() != stored_hash):
            self.send_error(403, message='The email address and password are invalid!')
            return


        token = yield self.generate_token(email)

        self.set_status(200)
        self.response['token'] = token['token']
        self.response['expiresIn'] = token['expiresIn']

        self.write_json()
