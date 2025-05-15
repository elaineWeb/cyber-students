from json import dumps
from tornado.escape import json_decode
from tornado.ioloop import IOLoop
from tornado.web import Application

from api.handlers.registration import RegistrationHandler

from .base import BaseTest

import urllib.parse

class RegistrationHandlerTest(BaseTest):

    @classmethod
    def setUpClass(self):
        self.my_app = Application([(r'/registration', RegistrationHandler)])
        super().setUpClass()

    def test_registration(self):
       
        email = 'test@test.com'
        display_name = 'testDisplayName'

        body = {
          'email': email,
          'password': 'testPassword',
          'displayName': display_name
        }

        response = self.fetch('/registration', method='POST', body=dumps(body))
        self.assertEqual(200, response.code)

        body_2 = json_decode(response.body)
        self.assertEqual(email, body_2['email'])

        #I only need this for debugging purposes
        print("Key = " + self.my_app.AES_KEY.hex() + " NAME = " + body_2['displayName'] + " ** EMAIL = " + email)

        'EMC - need to decrypt the display name'
        decodedName = self.decrypt_text(body_2['displayName'], self.my_app.AES_KEY, email)


        #self.assertEqual(display_name, body_2['displayName'])
        self.assertEqual(display_name, decodedName)

    def test_registration_without_display_name(self):
        email = 'test@test.com'

        body = {
          'email': email,
          'password': 'testPassword'
        }

        # EMC- I left the registration with the minimum required fields - email and password
        response = self.fetch('/registration', method='POST', body=dumps(body))
        self.assertEqual(200, response.code)

        body_2 = json_decode(response.body)

      
        self.assertEqual(email, body_2['email'])
        
        'EMC - need to decrypt the display name to complre to make sure it is the same and the encryption is working'
        decodedName = self.decrypt_text(body_2['displayName'], self.my_app.AES_KEY, email)   
        
        # check against the new value entered if there is no display name
        novalue = "NO display name entered"     
        self.assertEqual(novalue, decodedName)
        #self.assertEqual(email, body_2['displayName'])

    def test_registration_twice(self):
        body = {
          'email': 'test@test.com',
          'password': 'testPassword',
          'displayName': 'testDisplayName'
        }

        response = self.fetch('/registration', method='POST', body=dumps(body))
        self.assertEqual(200, response.code)

        response_2 = self.fetch('/registration', method='POST', body=dumps(body))
        self.assertEqual(409, response_2.code)
