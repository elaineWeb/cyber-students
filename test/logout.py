from json import dumps
from tornado.escape import json_decode, utf8
from tornado.gen import coroutine
from tornado.httputil import HTTPHeaders
from tornado.ioloop import IOLoop
from tornado.web import Application

from api.handlers.logout import LogoutHandler

from .base import BaseTest

import urllib.parse

class LogoutHandlerTest(BaseTest):

    @classmethod
    def setUpClass(self):
        self.my_app = Application([(r'/logout', LogoutHandler)])
        super().setUpClass()

    @coroutine
    def register(self):
        yield self.get_app().db.users.insert_one({
            'email': self.email,
            'password': self.password,
            'displayName': 'testDisplayName', 
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
        
        self.salt = ''
        #self.hash = ''

        # don't need the salt and hash for this test, but if I do need to use it this is what it should be  
        #self.salt = 'Eft9sTjMKBYgVD5BsYR2sA=='

        # this is a known value for my test - the hash for the password 'testPassword' with the salt 'Eft9sTjMKBYgVD5BsYR2sA=='
        self.hash = 'eP7VJext6P74t4k2KZ7kLVOsLDi7WhX3tA7FIOhChu8='
        
        self.token = 'testToken'

        IOLoop.current().run_sync(self.register)
        IOLoop.current().run_sync(self.login)

    def test_logout(self):
        headers = HTTPHeaders({'X-Token': self.token})
        body = {}

        response = self.fetch('/logout', headers=headers, method='POST', body=dumps(body))
        self.assertEqual(200, response.code)

    def test_logout_without_token(self):
        body = {}

        response = self.fetch('/logout', method='POST', body=dumps(body))
        self.assertEqual(400, response.code)

    def test_logout_wrong_token(self):
        headers = HTTPHeaders({'X-Token': 'wrongToken'})
        body = {}

        response = self.fetch('/logout', method='POST', body=dumps(body))
        self.assertEqual(400, response.code)

    def test_logout_twice(self):
        headers = HTTPHeaders({'X-Token': self.token})
        body = {}

        response = self.fetch('/logout', headers=headers, method='POST', body=dumps(body))
        self.assertEqual(200, response.code)

        response_2 = self.fetch('/logout', headers=headers, method='POST', body=dumps(body))
        self.assertEqual(403, response_2.code)
