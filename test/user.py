from json import dumps
from tornado.escape import json_decode, utf8
from tornado.gen import coroutine
from tornado.httputil import HTTPHeaders
from tornado.ioloop import IOLoop
from tornado.web import Application
import os
import hashlib
import base64

from api.handlers.user import UserHandler

from .base import BaseTest

import urllib.parse

class UserHandlerTest(BaseTest):

    @classmethod
    def setUpClass(self):
        self.my_app = Application([(r'/user', UserHandler)])
        super().setUpClass()

    @coroutine
    def register(self):
        import base64
        
        # Just testing the encryption and decryption of the display name
        yield self.get_app().db.users.insert_one({
            'email': self.email,
            'password': self.password,
            'displayName': self.encrypt_text(self.display_name, self.my_app.AES_KEY, aad=self.email),
            'disabilities' : self.encrypt_text('test', self.my_app.AES_KEY, aad=self.email),
            'fullName' : self.encrypt_text('test', self.my_app.AES_KEY, aad=self.email),
            'dob' : self.encrypt_text('test', self.my_app.AES_KEY, aad=self.email),
            'phoneNumber' : self.encrypt_text('test', self.my_app.AES_KEY, aad=self.email),
            'address': self.encrypt_text('test', self.my_app.AES_KEY, aad=self.email),
            'salt': self.salt,
            'hash': self.hash,
            'iterations': 100_000           
        })

    @coroutine
    def login(self):
        yield self.get_app().db.users.update_one({
            'email': self.email
        }, {
            '$set': { 'token': self.token, 'expiresIn': 2147483647 }
        })

    def setUp(self):
        super().setUp()


        self.email = 'test@test.com'
        self.password = 'testPassword'    
        
        ' EMC - DO not need to make the testing code so complicated - I just need to test the encryption and decryption of the display name'
        #self.pepper = self.pepper     #  base64.b64decode('F8a3RJIMMsCnZeUN0Rmpyg==')
        
        # Known values for your test
        #fixed_salt = os.urandom(16)  # or use a hardcoded salt if you want repeatability

        #fixed_salt = b'MyFixedSalt123456'
        #password_bytes = self.password.encode('utf-8')
          

        #combined = self.password.encode("utf-8") + self.my_app.pepper 

        #dk = hashlib.pbkdf2_hmac('sha256', combined, fixed_salt, 100_000)       
        #storedSalt = base64.b64encode(fixed_salt).decode()
        #stored_hash = base64.b64encode(dk).decode()
      
        self.display_name = 'testDisplayName'
        
        self.token = 'testToken'
        self.salt = '' #storedSalt
        self.hash = '' #stored_hash

        print("UserHandlerTest - SETUP - EMAIL - " + self.email + " - PASSWORD - " + self.password + " - SALT - " + self.salt + " - HASH - " + self.hash) # + " - PEPPER " + self.my_app.pepper)

        IOLoop.current().run_sync(self.register)
        IOLoop.current().run_sync(self.login)

    def test_user(self):
        headers = HTTPHeaders({'X-Token': self.token})

        response = self.fetch('/user', headers=headers)
        self.assertEqual(200, response.code)

        body_2 = json_decode(response.body)
        self.assertEqual(self.email, body_2['email'])

        self.assertEqual(self.display_name, body_2['displayName'])  #self.decrypt_text(body_2['displayName'], self.my_app.AES_KEY))

    def test_user_without_token(self):
        response = self.fetch('/user')
        self.assertEqual(400, response.code)

    def test_user_wrong_token(self):
        headers = HTTPHeaders({'X-Token': 'wrongToken'})

        response = self.fetch('/user')
        self.assertEqual(400, response.code)
