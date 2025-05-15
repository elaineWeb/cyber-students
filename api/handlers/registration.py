from json import dumps
from logging import info
from tornado.escape import json_decode, utf8
from tornado.gen import coroutine

from .base import BaseHandler

#EMC
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import base64  
import hashlib

# Fixed AES key (must be securely stored elsewhere in a real app)
AES_KEY = os.urandom(16)  # Replace this with your own fixed key

class RegistrationHandler(BaseHandler):

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
            display_name = body.get('displayName')
            if display_name is None:
                #display_name = email
                #Instead of adding the email to the display_name I changed to no display name entered as it is not secure and can make users vulnerable to spam, phishing, etc. 
                display_name = "NO display name entered"


            #ELAINE NEW CODE
            fullName = body.get('fullName')
            if fullName is None:
                fullName = "NO full_name entered"

            address = body.get('address')
            if address is None:
                address = "NO address entered"

            dob = body.get('dob')
            if dob is None:
                dob = "NO dob entered"

            disabilities = body.get('disabilities')
            if disabilities is None:
                disabilities = "NO disabilities entered"

            phoneNumber = body.get('phoneNumber')
            if phoneNumber is None:
                phoneNumber = "NO phone number entered"

            if not isinstance(display_name, str):
                raise Exception()
        except Exception as e:
            self.send_error(400, message='You must provide an email address, password and display name!')
            return

        if not email:
            self.send_error(400, message='The email address is invalid!')
            return

        if not password:
            self.send_error(400, message='The password is invalid!')
            return

        if not display_name:
            self.send_error(400, message='The display name is invalid!')
            return

        user = yield self.db.users.find_one({
          'email': email
        }, {})

        if user is not None:
            self.send_error(409, message='A user with the given email address already exists!')
            return

        #AES_KEY = self.readKey()
        AES_KEY = self.AES_KEY
        if AES_KEY is None:
            self.send_error(400, message='Error reading AES key!')
            return
        
        pepper = self.application.pepper
        print("TYPE =", type(pepper))      
        if pepper is None:
            self.send_error(400, message='Error reading PEPPER key!')
            return

        salt = os.urandom(16)  # Secure 128-bit salt
        
        #combined_pepper_and_password = password + self.PEPPER
        #password_bytes = combined_pepper_and_password.encode("utf-8")

        combined = password.encode("utf-8") + pepper 

        print("PASSWORD =", password)
        print("TYPE =", type(password))        

        # it is now in the correct config file so should not be blank
        if pepper is None:
            self.send_error(400, message='Error reading PEPPER key!')
            return

        #hash the combined password and pepper with the salt with 100,000 iterations
        dk = hashlib.pbkdf2_hmac('sha256', combined, salt, 100_000)
        SaltedPassword = base64.b64encode(salt).decode(), base64.b64encode(dk).decode()

        stotedSalt = base64.b64encode(salt).decode()
        stored_hash = base64.b64encode(dk).decode()


        ## Encrypt the display name using AES-GCM
        encryptName = self.encrypt_text(display_name, AES_KEY, email)
        if encryptName is None:
            self.send_error(400, message='Error encrypting display name!')
            return
        
        edisabilities = self.encrypt_text(disabilities, AES_KEY, email)
        if edisabilities is None:
            self.send_error(400, message='Error encrypting disabilities!')
            return
        
        efullName = self.encrypt_text(fullName, AES_KEY, email)
        if efullName is None:
            self.send_error(400, message='Error encrypting fullName!')
            return
        
        eaddress = self.encrypt_text(address, AES_KEY, email)
        if eaddress is None:
            self.send_error(400, message='Error encrypting address!')
            return
        
        edob = self.encrypt_text(dob, AES_KEY, email)
        if edob is None:
            self.send_error(400, message='Error encrypting dob!')
            return
        
        ephoneNumber = self.encrypt_text(phoneNumber, AES_KEY, email)
        if edob is None:
            self.send_error(400, message='Error encrypting phoneNumber!')
            return
        
        #save the encrypted values to the database with the hashed password and salt
        yield self.db.users.insert_one({
            'email': email,
            'password': SaltedPassword,
            'displayName': encryptName,
            'fullName': efullName,
            'address': eaddress,
            'dob': edob,
            'phoneNumber': ephoneNumber,
            'disabilities': edisabilities,
            'salt': stotedSalt,
            'hash': stored_hash,
            'iterations': 100_000
        })

        


        # decoded = self.decrypt_text(encryptName, AES_KEY)        

        self.set_status(200)
        self.response['email'] = email
        self.response['displayName'] = encryptName #display_name  #decoded 

        self.write_json()
